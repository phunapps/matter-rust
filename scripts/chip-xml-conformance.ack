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

# DoorLock legacy PIN/RFID/user-status/user-type commands (!USR).
DoorLock.Command.SetPINCode legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
DoorLock.Command.GetPINCode legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
DoorLock.Command.GetPINCodeResponse legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
DoorLock.Command.ClearPINCode legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
DoorLock.Command.ClearAllPINCodes legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
DoorLock.Command.SetRFIDCode legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
DoorLock.Command.GetRFIDCode legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
DoorLock.Command.GetRFIDCodeResponse legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
DoorLock.Command.ClearRFIDCode legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
DoorLock.Command.ClearAllRFIDCodes legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
DoorLock.Command.SetUserStatus legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
DoorLock.Command.GetUserStatus legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
DoorLock.Command.GetUserStatusResponse legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
DoorLock.Command.SetUserType legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
DoorLock.Command.GetUserType legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
DoorLock.Command.GetUserTypeResponse legacy !USR commands removed in 1.5.1; chip never generated them (absent from controller-clusters.matter at v1.3.0.0, v1.4.2.0, master) — acknowledged gap (spec rev 6)
