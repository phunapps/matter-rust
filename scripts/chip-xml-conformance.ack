# Acknowledged XML-ONLY items for scripts/chip-xml-conformance.py.
#
# One item per line:
#   <key> <reason>
# where <key> is the item exactly as the XML-ONLY section prints it, before
# its parenthesised detail:
#   <Cluster>.Attribute.<Name>   <Cluster>.Command.<Name>
#   <Cluster>.Event.<Name>       <Cluster>.Feature.<CODE>
#   <Cluster>.<Element>.<Field>
#
# XML-ONLY items are report-only (they never fail the run). Listing one here
# moves it to the ACKNOWLEDGED section, so XML-ONLY shows only new items. A
# line that matches nothing is reported under STALE-ACK. Acknowledging is not
# a decision to leave the element out for good: the reason says why it is
# absent today.

# WindowCovering AbsolutePosition (ABS, bit 3) is provisional in 1.4.2.
WindowCovering.Feature.ABS provisionalConform (ABS) in 1.4.2
WindowCovering.Attribute.PhysicalClosedLimitLift provisionalConform (ABS) in 1.4.2
WindowCovering.Attribute.PhysicalClosedLimitTilt provisionalConform (ABS) in 1.4.2
WindowCovering.Attribute.CurrentPositionLift provisionalConform (ABS) in 1.4.2
WindowCovering.Attribute.CurrentPositionTilt provisionalConform (ABS) in 1.4.2
WindowCovering.Attribute.InstalledOpenLimitLift provisionalConform (ABS) in 1.4.2
WindowCovering.Attribute.InstalledClosedLimitLift provisionalConform (ABS) in 1.4.2
WindowCovering.Attribute.InstalledOpenLimitTilt provisionalConform (ABS) in 1.4.2
WindowCovering.Attribute.InstalledClosedLimitTilt provisionalConform (ABS) in 1.4.2
WindowCovering.Command.GoToLiftValue provisionalConform (ABS) in 1.4.2
WindowCovering.Command.GoToTiltValue provisionalConform (ABS) in 1.4.2

# Thermostat ScheduleConfiguration (SCH, bit 3) and its weekly schedule.
Thermostat.Feature.SCH 1.4 feature absent from the 1.5.1 model; synthesise-vs-known-gap pending user decision
Thermostat.Attribute.StartOfWeek 1.4 feature absent from the 1.5.1 model; synthesise-vs-known-gap pending user decision
Thermostat.Attribute.NumberOfWeeklyTransitions 1.4 feature absent from the 1.5.1 model; synthesise-vs-known-gap pending user decision
Thermostat.Attribute.NumberOfDailyTransitions 1.4 feature absent from the 1.5.1 model; synthesise-vs-known-gap pending user decision
Thermostat.Command.SetWeeklySchedule 1.4 feature absent from the 1.5.1 model; synthesise-vs-known-gap pending user decision
Thermostat.Command.GetWeeklySchedule 1.4 feature absent from the 1.5.1 model; synthesise-vs-known-gap pending user decision
Thermostat.Command.ClearWeeklySchedule 1.4 feature absent from the 1.5.1 model; synthesise-vs-known-gap pending user decision
Thermostat.Command.GetWeeklyScheduleResponse 1.4 feature absent from the 1.5.1 model; synthesise-vs-known-gap pending user decision
