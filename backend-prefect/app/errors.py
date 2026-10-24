"""Errores de dominio. Cada uno sabe con qué código HTTP responder."""


class AuthFlowError(Exception):
    status_code = 401
    error_code = "auth_error"


class InvalidCredentials(AuthFlowError):
    error_code = "invalid_credentials"


class UserAlreadyExists(AuthFlowError):
    status_code = 409
    error_code = "user_already_exists"


class InvalidPreAuthToken(AuthFlowError):
    error_code = "invalid_pre_auth_token"


class InvalidAccessToken(AuthFlowError):
    error_code = "invalid_access_token"


class ReplayAttackDetected(AuthFlowError):
    status_code = 409
    error_code = "replay_attack_detected"


class InvalidSecondFactor(AuthFlowError):
    error_code = "invalid_second_factor"


class TooManyAttempts(AuthFlowError):
    status_code = 429
    error_code = "too_many_attempts"


class InvalidStateTransition(AuthFlowError):
    status_code = 409
    error_code = "invalid_state_transition"
