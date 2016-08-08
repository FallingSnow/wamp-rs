use URI;
use std::fmt;
use serde;

#[derive(Hash, Eq, PartialEq, Debug)]
pub enum Reason {
    InvalidURI,
    NoSuchProcedure,
    ProcedureAlreadyExists,
    NoSuchRegistration,
    NoSuchSubscription,
    InvalidArgument,
    SystemShutdown,
    CloseRealm,
    GoodbyeAndOut,
    NotAuthorized,
    AuthorizationFailed,
    NoSuchRealm,
    NoSuchRole,
    Cancelled,
    OptionNotAllowed,
    NoEligibleCallee,
    OptionDisallowedDiscloseMe,
    NetworkFailure,
    NormalClose,
    CustomReason(URI)
}


#[derive(Hash, Eq, PartialEq, Debug)]
pub enum ErrorType {
    Subscribe,
    Unsubscribe,
    Publish,
    Register,
    Unregister,
    Invocation,
    Call,
}

struct ErrorTypeVisitor;
struct ReasonVisitor;

impl Reason {
    #[inline]
    fn get_string(&self) -> &str {
        match *self {
            Reason::InvalidURI => "wamp.error.invalid_uri",
            Reason::NoSuchProcedure => "wamp.error.no_such_procedure",
            Reason::ProcedureAlreadyExists => "wamp.error.procedure_already_exists",
            Reason::NoSuchRegistration => "wamp.error.no_such_registration",
            Reason::NoSuchSubscription => "wamp.error.no_such_subscription",
            Reason::InvalidArgument => "wamp.error.invalid_argument",
            Reason::SystemShutdown => "wamp.error.system_shutdown",
            Reason::CloseRealm => "wamp.error.close_realm",
            Reason::GoodbyeAndOut => "wamp.error.goodbye_and_out",
            Reason::NotAuthorized => "wamp.error.not_authorized",
            Reason::AuthorizationFailed => "wamp.error.authorization_failed",
            Reason::NoSuchRealm => "wamp.error.no_such_realm",
            Reason::NoSuchRole => "wamp.error.no_such_role",
            Reason::Cancelled => "wamp.error.cancelled",
            Reason::OptionNotAllowed => "wamp.error.option_not_allowed",
            Reason::NoEligibleCallee => "wamp.error.no_eligible_callee",
            Reason::OptionDisallowedDiscloseMe => "wamp.error.option-disallowed.disclose_me",
            Reason::NetworkFailure => "wamp.error.network_failure",
            Reason::NormalClose => "wamp.close.normal",
            Reason::CustomReason(ref reason) => &reason.uri
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.get_string())
    }
}

/*-------------------------
         Reason
-------------------------*/

impl serde::Serialize for Reason {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer,
    {
        serializer.serialize_str(self.get_string())
    }
}

impl serde::Deserialize for Reason {
    fn deserialize<D>(deserializer: &mut D) -> Result<Reason, D::Error>
        where D: serde::Deserializer,
    {
        deserializer.deserialize(ReasonVisitor)
    }
}

impl serde::de::Visitor for ReasonVisitor {
    type Value = Reason;

    #[inline]
    fn visit_str<E>(&mut self, value: &str) -> Result<Reason, E>
        where E: serde::de::Error,
    {
        match value {
             "wamp.error.invalid_uri" => Ok(Reason::InvalidURI),
             "wamp.error.no_such_procedure" => Ok(Reason::NoSuchProcedure),
             "wamp.error.procedure_already_exists" => Ok(Reason::ProcedureAlreadyExists),
             "wamp.error.no_such_registration" => Ok(Reason::NoSuchRegistration),
             "wamp.error.no_such_subscription" => Ok(Reason::NoSuchSubscription),
             "wamp.error.invalid_argument" => Ok(Reason::InvalidArgument),
             "wamp.error.system_shutdown" => Ok(Reason::SystemShutdown),
             "wamp.error.close_realm" => Ok(Reason::CloseRealm),
             "wamp.error.goodbye_and_out" => Ok(Reason::GoodbyeAndOut),
             "wamp.error.not_authorized" => Ok(Reason::NotAuthorized),
             "wamp.error.authorization_failed" => Ok(Reason::AuthorizationFailed),
             "wamp.error.no_such_realm" => Ok(Reason::NoSuchRealm),
             "wamp.error.no_such_role" => Ok(Reason::NoSuchRole),
             "wamp.error.cancelled" => Ok(Reason::Cancelled),
             "wamp.error.option_not_allowed" => Ok(Reason::OptionNotAllowed),
             "wamp.error.no_eligible_callee" => Ok(Reason::NoEligibleCallee),
             "wamp.error.option-disallowed.disclose_me" => Ok(Reason::OptionDisallowedDiscloseMe),
             "wamp.error.network_failure" => Ok(Reason::NetworkFailure),
             "wamp.close.normal" => Ok(Reason::NormalClose),
             x => Ok(Reason::CustomReason(URI::new(x)))
        }
    }

}


/*-------------------------
         ErrorType
-------------------------*/

impl serde::Serialize for ErrorType {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer,
    {
        let ser_int = match *self {
             ErrorType::Subscribe => 32,
             ErrorType::Unsubscribe => 34,
             ErrorType::Publish => 16,
             ErrorType::Register => 64,
             ErrorType::Unregister => 66,
             ErrorType::Invocation => 68,
             ErrorType::Call => 48,
        };
        serializer.serialize_u64(ser_int)
    }
}

impl serde::Deserialize for ErrorType {
    fn deserialize<D>(deserializer: &mut D) -> Result<ErrorType, D::Error>
        where D: serde::Deserializer,
    {
        deserializer.deserialize(ErrorTypeVisitor)
    }
}

impl serde::de::Visitor for ErrorTypeVisitor {
    type Value = ErrorType;

    #[inline]
    fn visit_u64<E>(&mut self, value: u64) -> Result<ErrorType, E>
        where E: serde::de::Error,
    {
        match value {
            32 => Ok(ErrorType::Subscribe),
            34 => Ok(ErrorType::Unsubscribe),
            16 => Ok(ErrorType::Publish),
            64 => Ok(ErrorType::Register),
            66 => Ok(ErrorType::Unregister),
            68 => Ok(ErrorType::Invocation),
            48 => Ok(ErrorType::Call),
            x => Err(serde::de::Error::custom(format!("Invalid message error type: {}", x)))
        }
    }

}