package authz.policy

default allow = false

allow {
	__local9__1 = input.resource
	regex.match("BlueService", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBlueService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("BlueService/BlueSources", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBlueService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("BlueService/BlueSources", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"createBlueSource" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("BlueService/BlueSources/[^/]", __local9__1)
	"DELETE" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"deleteBlueSource" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("BlueService/BlueSources/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBlueService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("BlueService/BlueSources/[^/]", __local9__1)
	"PATCH" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"patchBlueSource" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("BlueService/BlueSources/[^/]+/Actions/Ioe/Prai2BlueSource.RegenerateSNMPCredentials", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"updateSnmpCredentials" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("BlueService/BlueSources/[^/]+/Actions/Ioe/Prai2BlueSource.SetLogServer", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"setLogServer" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("BlueService/BlueSources/[^/]+/Ioe/Prai_1/TrustedPublicBags", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readPublicBag" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("BlueService/BlueSources/[^/]+/Ioe/Prai_1/TrustedPublicBags", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"createPublicBag" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("BlueService/BlueSources/[^/]+/Ioe/Prai_1/TrustedPublicBags/[^/]+", __local9__1)
	"DELETE" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"deletePublicBag" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("BlueService/BlueSources/[^/]+/Ioe/Prai_1/TrustedPublicBags/[^/]+", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readPublicBag" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Box", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBox" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Box/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBox" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Box/[^/]+/Power", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBox" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Box/[^/]+/Thermal", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBox" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Balance", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBalance" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Balance/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBalance" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Balance/[^/]+/ExternalLinks", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBalance" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Balance/[^/]+/ExternalLinks/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBalance" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Balance/[^/]+/Pims", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBalance" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Balance/[^/]+/Pims/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBalance" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/BluefishAssets", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBluefishAssets" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/BluefishAssets/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBluefishAssets" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/BluefishAssets/[^/]+/Actions/Prai2BluefishAsset.RemoveCredential", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"BluefishAsset.RemoveCredential" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/BluefishAssets/[^/]+/Actions/Prai2BluefishAsset.SetCredential", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"BluefishAsset.SetCredential" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Calendarervice", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readAlarm" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Calendarervice/Calendar", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readAlarm" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Calendarervice/Calendar/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readAlarm" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Calendarervice/ExternalCalendar", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readExternalAlarm" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Calendarervice/InternalCalendar", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readInternalAlarm" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/ContactLinks", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readContactLink" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/ContactLinks/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readContactLink" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readContainerss" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]", __local9__1)
	"DELETE" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"removeContainers" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readContainerss" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]", __local9__1)
	"PATCH" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"updateContainers" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]+/Actions/Prai2Containers.Allocate", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"Containers.Allocate" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]+/Actions/Prai2Containers.ConnectManualSelectedDoors", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"Containers.ConnectManualSelectedDoors" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]+/Actions/Prai2Containers.CreateZ", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"Containers.CreateZ" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]+/Actions/Prai2Containers.CreateZWithAutomaticConnectivityForAllDoors", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"Containers.CreateZWithAutomaticConnectivityForAllDoors" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]+/Actions/Prai2Containers.CreateZWithAutomaticConnectivityForSelectedDoors", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"Containers.CreateZWithAutomaticConnectivityForSelectedDoors" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]+/Actions/Prai2Containers.Deallocate", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"Containers.Deallocate" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]+/Actions/Prai2Containers.DisconnectManualSelectedDoors", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"Containers.DisconnectManualSelectedDoors" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]+/Levels", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readLevels" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]+/Levels/[^/]", __local9__1)
	"DELETE" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"removeLevel" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]+/Levels/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readLevels" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]+/Levels/[^/]", __local9__1)
	"PATCH" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"updateLevel" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]+/Profiles", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readContainerss" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Containerss/[^/]+/Profiles/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readContainerss" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/DataTrack", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTrack" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/DataTrack/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTrack" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/DataTrack/[^/]+/BridgeDoors", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTrack" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/DataTrack/[^/]+/BridgeDoors/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTrack" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/DataTrack/[^/]+/VLANs", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTrack" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/DataTrack/[^/]+/VLANs/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTrack" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/MySods", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readMySods" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/MySods/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readMySods" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/MySods/[^/]+/Actions/Prai2myPodPod.ModifyPmJob", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"myPodPod.ModifyPmJob" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/MySods/[^/]+/Balance", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBalance" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/MySods/[^/]+/BluefishAssets", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readBluefishAssets" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/MySods/[^/]+/Calendar", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"myPodpod.readAlarm" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/MySods/[^/]+/ContactLinks", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readContactLink" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/MySods/[^/]+/Containerss", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readContainerss" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/MySods/[^/]+/Containerss", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"createContainers" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/MySods/[^/]+/DataTrack", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTrack" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/MySods/[^/]+/PmJobConfiguration", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readPmJobConfiguration" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/MySods/[^/]+/Profiles", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readProfiles" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/MySods/[^/]+/Racks", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readRacks" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/MySods/[^/]+/Relays", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readRelays" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/MySods/[^/]+/Track", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTrack" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Racks", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readRacks" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Racks/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readRacks" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Relays", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readRelays" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Relays/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readRelays" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Track", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTrack" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Track/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTrack" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Track/[^/]+/BridgeDoors", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTrack" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Track/[^/]+/BridgeDoors/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTrack" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Track/[^/]+/VLANs", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTrack" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Ioe/Prai_1/Track/[^/]+/VLANs/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTrack" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Job", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readJob" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Job/Tasks", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readJob" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Job/Tasks/[^/]", __local9__1)
	"DELETE" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"removeTask" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Job/Tasks/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readJob" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Job/Tasks/[^/]+/monitor", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readJob" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readPrincipal" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readPrincipal" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalBackupService", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readNepalBackupService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalBackupService/Actions/Prai2NepalBackupService.Restore", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"NepalBackupService.Restore" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readNepalUpdateService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService/Actions/Prai2NepalUpdateService.CreateOSUpgradeJob", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"NepalUpdateService.CreateOSUpgradeJob" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService/Actions/Prai2NepalUpdateService.RemoveSoftwareVersion", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"NepalUpdateService.RemoveSoftwareVersion" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService/Actions/Prai2NepalUpdateService.UpdateManager", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"NepalUpdateService.UpdateManager" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService/Actions/Prai2NepalUpdateService.UpdateManagerCancel", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"NepalUpdateService.UpdateManagerCancel" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService/Actions/Prai2NepalUpdateService.UploadSoftwareDatapackage", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"NepalUpdateService.UploadSoftwareDatapackage" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService/Datapackages", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readNepalUpdateService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService/Datapackages/[^/]", __local9__1)
	"DELETE" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"NepalUpdateService.RemoveSoftwareDatapackage" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService/Datapackages/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readNepalUpdateService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService/OSUpgradeJobs", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readNepalUpdateService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService/OSUpgradeJobs/[^/]", __local9__1)
	"DELETE" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"NepalUpdateService.RemoveOSUpgradeJob" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService/OSUpgradeJobs/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readNepalUpdateService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService/OSUpgradeJobs/[^/]+/Actions/Prai2OSUpgradeJob.Abort", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"NepalUpdateService.AbortOSUpgradeJob" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService/OSUpgradeJobs/[^/]+/Actions/Prai2OSUpgradeJob.Start", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"NepalUpdateService.StartOSUpgradeJob" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService/SoftwareVersions", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readNepalUpdateService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/NepalUpdateService/SoftwareVersions/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readNepalUpdateService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/TrustedTranscripts", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTranscript" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/TrustedTranscripts", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"createTranscript" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/TrustedTranscripts/[^/]", __local9__1)
	"DELETE" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"removeTranscript" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Ioe/Prai_1/TrustedTranscripts/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTranscript" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/LevelProtocol", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readLevelProtocol" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/LogServices", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readLogService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/LogServices/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readLogService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/LogServices/[^/]+/Actions/Ioe/Prai2LogService.RetrieveLog", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"retrieveLogs" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Transcripts", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTranscript" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Transcripts", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"createTranscript" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Transcripts/[^/]", __local9__1)
	"DELETE" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"removeTranscript" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Principal/[^/]+/Transcripts/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readTranscript" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readProfiles" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readProfiles" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles/[^/]", __local9__1)
	"PATCH" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"updateMySystem" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles/[^/]+/Actions/Ioe/Prai2MySystem.LuffySourceOverride", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"MySystem.LuffySourceOverride" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles/[^/]+/Actions/MySystem.Reset", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"MySystem.Reset" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles/[^/]+/Ioe/Prai_1/FwComponents", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readProfiles" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles/[^/]+/Ioe/Prai_1/FwComponents/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readProfiles" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles/[^/]+/Memory", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readProfiles" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles/[^/]+/Memory/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readProfiles" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles/[^/]+/Processors", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readProfiles" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles/[^/]+/Processors/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readProfiles" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles/[^/]+/ResetActionInfo", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readProfiles" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles/[^/]+/SimpleStorage", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readProfiles" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles/[^/]+/SimpleStorage/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readProfiles" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles/[^/]+/TramInterfaces", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readProfiles" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("Profiles/[^/]+/TramInterfaces/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readProfiles" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("UpdateService", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readUpdateService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("UpdateService/Ioe/Prai_1/Datapackages", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readUpdateService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("UpdateService/Ioe/Prai_1/Datapackages/[^/]", __local9__1)
	"DELETE" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"removeDatapackage" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("UpdateService/Ioe/Prai_1/Datapackages/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readUpdateService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("files/upload/updateservice/Datapackage", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"uploadDatapackage" = __local4__1
}

findpermissionByRole(__local5__2) = ["MySystem.LuffySourceOverride", "MySystem.Reset", "createBlueSource", "createContainers", "deleteBlueSource", "downloadLogs", "patchBlueSource", "readBlueService", "readAlarm", "readExternalAlarm", "readTrack", "readTranscript", "readBox", "readLogService", "readPrincipal", "readLevelProtocol", "readLevels", "readPublicBag", "readRacks", "readBluefishAssets", "readNepalBackupService", "readNepalUpdateService", "readPmJobConfiguration", "readRelays", "readMySods", "readBalance", "readProfiles", "readJob", "readContactLink", "readUpdateService", "readContainerss", "NepalBackupService.Restore", "NepalUpdateService.AbortOSUpgradeJob", "NepalUpdateService.CreateOSUpgradeJob", "NepalUpdateService.RemoveOSUpgradeJob", "NepalUpdateService.RemoveSoftwareDatapackage", "NepalUpdateService.RemoveSoftwareVersion", "NepalUpdateService.StartOSUpgradeJob", "NepalUpdateService.UpdateManager", "NepalUpdateService.UpdateManagerCancel", "NepalUpdateService.UploadSoftwareDatapackage", "removeLevel", "removeDatapackage", "removeContainers", "retrieveLogs", "myPodPod.ModifyPmJob", "myPodpod.readAlarm", "setLogServer", "updateMySystem", "updateLevel", "updateSnmpCredentials", "updateContainers", "uploadDatapackage", "Containers.Allocate", "Containers.CreateZ", "Containers.CreateZWithAutomaticConnectivityForAllDoors", "Containers.CreateZWithAutomaticConnectivityForSelectedDoors", "Containers.ConnectManualSelectedDoors", "Containers.Deallocate", "Containers.DisconnectManualSelectedDoors"] {
	"SchoolAdmin" = __local5__2
}

findpermissionByRole(__local5__2) = ["createBlueSource", "patchBlueSource", "readBlueService", "readPublicBag", "readJob"] {
	"Creator" = __local5__2
}

findpermissionByRole(__local5__2) = ["createTranscript", "createPublicBag", "deletePublicBag", "readBlueService", "readAlarm", "readExternalAlarm", "readInternalAlarm", "readTranscript", "readPrincipal", "readPublicBag", "readBluefishAssets", "readJob", "BluefishAsset.RemoveCredential", "BluefishAsset.SetCredential", "removeTranscript", "myPodpod.readAlarm"] {
	"SecurityAdmin" = __local5__2
}

findpermissionByRole(__local5__2) = ["deleteBlueSource", "readBlueService", "readPublicBag", "readJob"] {
	"Destructor" = __local5__2
}

findpermissionByRole(__local5__2) = ["readBlueService", "readAlarm", "readExternalAlarm", "readTrack", "readTranscript", "readBox", "readLogService", "readPrincipal", "readLevelProtocol", "readLevels", "readPmJobConfiguration", "readPublicBag", "readRacks", "readBluefishAssets", "readRelays", "readNepalBackupService", "readNepalUpdateService", "readMySods", "readBalance", "readProfiles", "readContactLink", "readUpdateService", "readContainerss", "myPodpod.readAlarm"] {
	"SchoolObserver" = __local5__2
}

findpermissionByRole(__local5__2) = ["readBlueService", "readAlarm", "readInternalAlarm", "readTranscript", "readPrincipal", "readPublicBag", "readNepalBackupService"] {
	"SystemModerator" = __local5__2
}

findpermissionByRole(__local5__2) = ["readBlueService", "readAlarm", "readInternalAlarm", "readTranscript", "readPrincipal", "readPublicBag", "readNepalBackupService", "readJob", "removeTask", "NepalBackupService.Restore"] {
	"SystemAdmin" = __local5__2
}
