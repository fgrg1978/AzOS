# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# config/Kconfig.robot — Robot domain: robot type, brain link, safety layer
#
# Shown only for DOMAIN_ROBOT (config/Kconfig.domain). The menu is hidden
# with `visible if`, not wrapped in `if DOMAIN_ROBOT`: a hidden option keeps
# its unconditional default, so the integers below are written to .config in
# every domain, and a hidden `bool` that is n reaches azos_limits as
# `false` (crates/core/limits/build.rs fills in every hideable bool that
# .config leaves out). Wrapping in `if` would drop the integers from a
# Generic .config instead.

menu "Robot"
    visible if DOMAIN_ROBOT

# ---------------------------------------------------------------------------
# Robot type
# ---------------------------------------------------------------------------

choice
    prompt "Robot type"
    default ROBOT_NONE
    help
      The robot type the safety envelope starts with
      (domains/robot/behavior/src/safety.rs, ROBOT_TYPE; the value comes
      from ROBOT_TYPE_ID). It selects the type-specific checks
      `safety_check` runs every tick and the motor cap `motor_envelope`
      applies. No production code changes the type at run time today:
      `safety_set_robot_type` is called only by host tests. So before this
      option every image ran the wheeled checks, and the drone and
      humanoid checks were reachable only from host tests.

      The brain-link status packet reports this type
      (`safety_robot_type()`, kernel/src/tasks/behavior.rs; wave 11).

    config ROBOT_NONE
        bool "None (no platform chosen at build time)"
        help
          No mechanical platform is fixed. The envelope starts with the
          wheeled checks and the wheeled motor cap
          (SAFETY_WHEELED_MAX_SPEED_PCT), the tightest one, as every
          image did before this option existed: the same value as Wheeled.

    config ROBOT_WHEELED
        bool "Wheeled (2-channel differential drive)"
        help
          Two- or four-wheel differential drive. Actuator output:
          (speed_l, speed_r). Wheeled checks and the wheeled motor cap.

    config ROBOT_DRONE
        bool "Drone (4-channel quadrotor PWM)"
        help
          Quadrotor. The envelope starts with the drone checks
          (`check_drone`) and without the wheeled motor cap on the
          differential-drive path.

    config ROBOT_HUMANOID
        bool "Humanoid (N-channel joint angles)"
        help
          Multi-joint robot. The envelope starts with the humanoid checks
          (`check_humanoid`) and without the wheeled motor cap on the
          differential-drive path. There is no inverse kinematics in the
          tree.

    config ROBOT_ACKERMANN
        bool "Ackermann (car-like, 2-channel: throttle + steering)"
        help
          Rear-wheel drive with front steering. Same envelope as Wheeled
          (wheeled checks and the wheeled motor cap).

endchoice

config ROBOT_TYPE_ID
    int
    default 1 if ROBOT_DRONE
    default 2 if ROBOT_HUMANOID
    default 3 if ROBOT_ACKERMANN
    default 0
    help
      The robot type as the safety layer numbers it (ROBOT_TYPE_* in
      domains/robot/behavior/src/safety.rs and brain_protocol.rs):
      0 wheeled, 1 drone, 2 humanoid, 3 ackermann. No prompt: derived from
      the choice above, and 0 in every other domain, so a non-robot image
      keeps the starting type every image had before.

# ---------------------------------------------------------------------------
# Brain link
# ---------------------------------------------------------------------------

source "config/Kconfig.brain"

# ---------------------------------------------------------------------------
# Safety layer and motor control loop
# ---------------------------------------------------------------------------

menu "Safety layer and motor control"

config SAFETY_COMMS_TIMEOUT_S
    int "Safety comms timeout (seconds)"
    range 1 600
    default 5
    help
      domains/robot/behavior/src/safety.rs, SAFETY_COMMS_TIMEOUT_TICKS =
      TIMER_FREQ x this, so the time is the same on every board (a raw
      tick count was 5 s on QEMU, 7.5 s on the VF2, 1.25 s on the K1).
      No safety check reads the wheeled comms timeout today: the wheeled
      robot's comms-loss stop is rt_motor's own (unlatched, unrecorded).
      Wave 11: was SAFETY_COMMS_TIMEOUT_TICKS, read by no code.

config SAFETY_DRONE_COMMS_TIMEOUT_S
    int "Drone comms timeout (seconds)"
    range 1 600
    default 3
    help
      domains/robot/behavior/src/safety.rs,
      SAFETY_DRONE_COMMS_TIMEOUT_TICKS = TIMER_FREQ x this. `check_drone`
      returns ReturnToLaunch (CommsTimeout) when the last brain command is
      older than this. Wave 11: was SAFETY_DRONE_COMMS_TIMEOUT_TICKS, read
      by no code (the layer used a literal 3 s).

config PID_DT_MS
    int "Motor PID loop delta-T (ms)"
    range 1 1000
    default 10
    help
      crates/drivers/actuator/src/motor_pid.rs, PID_DT_MS: the period the
      motor PID reports in its init line, and the delta-T `motor_pid_tick`
      uses when the timer frequency is 0. With a running timer the loop
      measures its real interval from the timer instead, so on every
      board in the tree this value changes the init line and nothing else.
      Wave 11: the file used its own literal 10 before.

config ML_REPLY_TIMEOUT_US
    int "Behavior loop: ML service reply timeout (us)"
    range 1000 100000
    default 10000
    help
      kernel/src/behavior_ml.rs, ML_REPLY_TIMEOUT_US: how long one
      behavior-loop cycle waits for the ring-3 ML service's verdict before
      it treats the service as absent for that cycle (10 % of the 100 ms
      loop period at the default). The service's own work and the round
      trip are a few thousand instructions each ([BSTEP] measures both).
      Wave 11: was a literal.

config MOTOR_COMMANDER_EXIT_STOP
    bool "A dead motor commander's wheels go to a safe stop"
    default y if DOMAIN_ROBOT
    default n
    help
      Owner decision (wave 15): when a ring-3 task that commanded a wheel
      through the typed motor calls (560, 576, 584) exits or dies with
      that wheel at a non-zero duty, its exit stops the wheel (duty 0,
      coast) and writes a durable SAFETY_ESTOP record, action 14
      (commander lost: the task and the wheels in its detail). It does
      NOT latch the e-stop: the machine is stopped, not locked, and a
      restarted commander drives again (rt_motor's own SAFE STOP has the
      same contract). rt_motor_task rewrites the wheels every tick only
      while its command channel is live, so without this a ring-3 duty
      written after its watchdog fired stays on the channel.

      Cost: one atomic store per typed motor call, and per task exit one
      compare-and-swap per wheel (MAX_MOTORS, 4); a stop and a record
      only when the dying task commanded a wheel. No RAM beyond 4 B per
      wheel. Turn it off only for a robot whose ring-3 commander is meant
      to leave its last duty running after it exits.

endmenu # Safety layer and motor control

# ---------------------------------------------------------------------------
# RC receiver input and geofence (wave 15)
# ---------------------------------------------------------------------------

menu "RC input and geofence"

config RC_INPUT
    bool "RC receiver feeds the safety path"
    default y if DOMAIN_ROBOT
    default n
    help
      Wires the RC receiver (domains/robot/drivers/src/rc.rs) into the
      behavior loop (kernel/src/tasks/rc_safety.rs; the policy is
      domains/robot/behavior/src/rc_link.rs): a receiver failsafe or a link
      silent for RC_LINK_TIMEOUT_MS latches the e-stop (when
      RC_FAILSAFE_ESTOP), the kill switch latches it on every robot type,
      and with the mode switch high the sticks drive: the arbiter ranks them
      below L0 and L1's stop and above the brain and autonomy, and they
      reach the motors only through the motor envelope and the actuation
      gate. Each latch writes a durable SAFETY_ESTOP record (action 12 link
      loss, 13 kill switch).

      Nothing acts before the first frame arrives through rc_feed_byte (the
      SBUS byte source a board's UART receive interrupt calls; QEMU feeds
      it from a smoke task), so a robot without a transmitter is not held
      stopped.

      Cost: one rc_read and a few compares per behavior tick (100 ms) and a
      25-byte frame buffer. n compiles the policy, the kernel hook and the
      receiver init out (kernel feature `rc-input`); the flight controller
      then sees no RC link and fails closed.

config RC_FAILSAFE_ESTOP
    bool "RC link loss latches the e-stop"
    default n if ROBOT_DRONE
    default y
    help
      On a ground robot, stopping is the safe reaction to losing the
      transmitter. On a drone, stopping the motors drops it: there the
      flight controller's own reaction (return to launch,
      domains/robot/flight/src/failsafe.rs) is the right one, so the
      default is n for ROBOT_DRONE. The kill switch latches either way.
      No cost either way.

config RC_LINK_TIMEOUT_MS
    int "RC link timeout (ms)"
    range 20 5000
    default 300 if PROFILE_EMBEDDED
    default 500
    help
      With a link established, no fresh frame for this long is link loss
      (the receiver's own failsafe bit counts at once). SBUS sends a frame
      every 7-14 ms, so 500 ms is ~40 missed frames: long enough to ride
      out interference, short enough that the robot does not travel far
      uncontrolled. The embedded profile's smaller, slower robots get
      300 ms. The behavior loop samples every 100 ms, so a value under
      100 acts at the next tick. No RAM or instruction cost.

config RC_MODE_CHANNEL
    int "RC channel of the manual-override switch (1-16, 0 = none)"
    range 0 16
    default 5
    help
      With this channel above RC_SWITCH_HIGH_US the sticks drive (manual
      override of the brain); below it the brain drives. 0 disables manual
      control: the receiver is then only a failsafe and a kill switch.
      Channel 5 is the conventional mode switch.

config RC_KILL_CHANNEL
    int "RC channel of the kill switch (1-16, 0 = none)"
    range 0 16
    default 6
    help
      Above RC_SWITCH_HIGH_US this channel latches the e-stop (action 13).
      The latch holds until an operator releases it, like every stop.
      0 disables the RC kill switch.

config RC_SWITCH_HIGH_US
    int "RC switch threshold (us)"
    range 1100 1950
    default 1700
    help
      A switch channel above this pulse width is on. 1700 leaves neutral
      (1500) and a three-position switch's middle position well below it.

config RC_DRIVE_CHANNEL
    int "RC channel of the drive (forward/back) stick (1-16)"
    range 1 16
    default 2
    help
      Manual override: this stick's deflection from 1500 us is the forward
      speed. Channel 2 (pitch, self-centring on a mode-2 transmitter) is the
      default, so letting go of the stick stops the robot.

config RC_STEER_CHANNEL
    int "RC channel of the steering stick (1-16)"
    range 1 16
    default 1
    help
      Manual override: this stick's deflection turns the robot by
      differential mixing (left = drive + steer, right = drive - steer).

config RC_STICK_DEADBAND_US
    int "RC stick deadband (us)"
    range 0 200
    default 20
    help
      Deflections within this many microseconds of 1500 read as zero, so a
      stick that does not centre exactly does not creep the robot.

config RC_STICK_FULL_SCALE_PCT
    int "RC stick full-deflection speed (percent)"
    range 1 100
    default 100
    help
      The speed full stick deflection ASKS for. The motor envelope still
      clamps it to the robot type's cap (SAFETY_WHEELED_MAX_SPEED_PCT, the
      low-confidence cap and the degrade level): this is a request, not a
      bound. Lower it to give a novice operator less authority.

config GEOFENCE
    bool "On-board geofence armed at the home fix"
    default y if DOMAIN_ROBOT
    default n
    help
      Arms the circular geofence (domains/robot/behavior/src/safety.rs, E03)
      at the first trusted GPS fix of the boot, with radius
      GEOFENCE_RADIUS_M. Leaving it latches the e-stop with a durable
      SAFETY_ESTOP record (action 8, detail = metres beyond the fence), and
      the actuation gate then refuses every motor write. Before this option
      nothing armed the fence on a normal boot.

      Cost: one fence evaluation per behavior tick (an integer square root
      only on a breach) and 16 bytes of state. n compiles the fence, its
      checks in safety_check and the kernel hook out (kernel feature
      `geofence`).

config GEOFENCE_RADIUS_M
    int "Geofence radius (m)"
    range 1 100000
    default 300 if ROBOT_DRONE
    default 100
    help
      The fence is a circle of this radius around the home fix. A drone
      needs more room than a ground robot for the same mission, and its
      breach reaction (return to launch) flies back from beyond the edge.
      No cost.

config GEOFENCE_MIN_SATELLITES
    int "Geofence: minimum satellites for a trusted fix"
    range 4 32
    default 4
    help
      The fence neither arms nor acts on a fix with fewer satellites in
      use. 4 is the fewest that fix a 3-D position plus the receiver clock;
      raise it where multipath makes a 4-satellite fix wander. Was the
      literal GEOFENCE_MIN_SATELLITES = 4 in safety.rs. No cost.

endmenu # RC input and geofence

comment "Fleet OTA has no build-time option: tools/fleet_ota_deploy.py"

endmenu # Robot
