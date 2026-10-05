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

endmenu # Safety layer and motor control

comment "Fleet OTA has no build-time option: tools/fleet_ota_deploy.py"

endmenu # Robot
