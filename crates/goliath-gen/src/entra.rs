//! Entra sign-ins in the Azure Monitor diagnostic envelope.
use crate::{Organization, data, random::Random, time::timestamp};
use serde_json::{Value, json};

/// Reproducible interactive and non-interactive user sign-ins.
pub struct Entra {
    random: Random,
}

impl Entra {
    /// Starts a stream from `seed`.
    pub fn new(seed: u64) -> Self {
        Self {
            random: Random::new(seed),
        }
    }

    /// Emits a sign-in for a user in `org`.
    ///
    /// # Panics
    /// Panics if `user` is not an index into `org.users`.
    pub fn record(&mut self, org: &Organization, user: usize, time_ms: i64) -> Value {
        let user = &org.users[user];
        let office = &org.offices[user.office];
        let host = &org.hosts[user.workstation];
        let app = self.random.pick(data::entra_apps());
        let (code, reason) = if self.random.chance(0.97) {
            (0, "")
        } else {
            *self.random.pick(&[
                (50126, "Invalid username or password."),
                (50074, "Strong authentication is required."),
                (50140, "Keep me signed in interrupt."),
            ])
        };
        let interactive = self.random.chance(0.7);
        json!({"time": timestamp(time_ms, 'T'), "resourceId": format!("/tenants/{}/providers/Microsoft.aadiam", org.tenant_id),
        "operationName": "Sign-in activity", "operationVersion": "1.0",
        "category": if interactive { "SignInLogs" } else { "NonInteractiveUserSignInLogs" },
        "tenantId": org.tenant_id, "resultType": code.to_string(), "resultSignature": "None", "resultDescription": reason,
        "durationMs": 0, "callerIpAddress": office.egress, "correlationId": self.random.guid(), "identity": user.display_name,
        "Level": 4, "location": office.country, "properties": {
            "id": self.random.guid(), "createdDateTime": timestamp(time_ms, 'T'), "userDisplayName": user.display_name,
            "userPrincipalName": user.upn, "userId": user.object_id, "appId": app.0, "appDisplayName": app.1,
            "resourceId": app.0, "resourceDisplayName": app.1, "ipAddress": office.egress,
            "status": {"errorCode": code, "failureReason": reason}, "clientAppUsed": "Browser", "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "deviceDetail": {"deviceId": host.device_id, "displayName": host.name, "operatingSystem": "Windows11", "isCompliant": true, "isManaged": true},
            "location": {"city": office.city, "countryOrRegion": office.country, "geoCoordinates": {"latitude": office.coordinates.0, "longitude": office.coordinates.1}},
            "authenticationRequirement": "multiFactorAuthentication", "isInteractive": interactive, "riskLevelDuringSignIn": "none", "riskState": "none"
        }})
    }
}
