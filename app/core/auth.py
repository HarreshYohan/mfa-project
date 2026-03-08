from webauthn import generate_registration_options, verify_registration_response
from webauthn.helpers.structs import RegistrationCredential

RP_NAME = "Enterprise MFA System"
RP_ID = "localhost" # This must match your live domain later [cite: 202]
ORIGIN = "http://localhost:8000"

def get_reg_options(user_id: str, username: str):
    return generate_registration_options(
        rp_name=RP_NAME,
        rp_id=RP_ID,
        user_id=user_id,
        user_name=username,
    )