"""
Generate self-signed SAML assertions for SAP SuccessFactors OAuth bearer authentication.

This helper remains standalone until ENT-12300 wires self-signed assertion auth into the
SAP SuccessFactors token acquisition flow in ``SAPSuccessFactorsAPIClient``.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import signxml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

SAML_ASSERTION_NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:assertion'
XMLDSIG_NAMESPACE = 'http://www.w3.org/2000/09/xmldsig#'
SAML_AUTHN_CONTEXT_UNSPECIFIED = 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified'
NS_SAML = f'{{{SAML_ASSERTION_NAMESPACE}}}'
NS_DS = f'{{{XMLDSIG_NAMESPACE}}}'


class SAMLAssertionGenerationError(Exception):
    """
    Raised when SAML assertion construction or signing fails.
    """


class InvalidPrivateKeyError(SAMLAssertionGenerationError):
    """
    Raised when the provided RSA private key is malformed or invalid.
    """


def _load_rsa_private_key(
    private_key_pem: str,
    private_key_passphrase: Optional[str] = None,
) -> Optional[bytes]:
    """
    Parse and validate the RSA private key used to sign the assertion.

    Returns the passphrase bytes expected by ``signxml`` after verifying that the PEM contains
    an RSA private key.
    """
    try:
        passphrase_bytes = private_key_passphrase.encode('utf-8') if private_key_passphrase else None
        key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=passphrase_bytes,
        )
    except Exception as exc:
        raise InvalidPrivateKeyError(f'Failed to load RSA private key: {str(exc)}') from exc

    if not isinstance(key, rsa.RSAPrivateKey):
        raise InvalidPrivateKeyError('Provided key is not an RSA private key.')

    return passphrase_bytes


def _build_saml_assertion(
    client_id: str,
    user_id: str,
    audience_value: str,
    token_url: str,
    issue_instant: str,
    not_before: str,
    not_on_or_after: str,
    assertion_id: str,
) -> etree._Element:
    """
    Construct the unsigned SAML 2.0 assertion XML tree in schema-valid element order.
    """
    assertion = etree.Element(
        f'{NS_SAML}Assertion',
        attrib={
            'ID': assertion_id,
            'Version': '2.0',
            'IssueInstant': issue_instant,
        },
        nsmap={'ds': XMLDSIG_NAMESPACE, 'saml': SAML_ASSERTION_NAMESPACE},
    )

    issuer = etree.SubElement(assertion, f'{NS_SAML}Issuer')
    issuer.text = client_id

    # signxml replaces this placeholder in-place, which keeps the Signature immediately after
    # the Issuer as required by the SAML assertion schema.
    etree.SubElement(assertion, f'{NS_DS}Signature', attrib={'Id': 'placeholder'})

    subject = etree.SubElement(assertion, f'{NS_SAML}Subject')
    name_id = etree.SubElement(
        subject,
        f'{NS_SAML}NameID',
        attrib={'Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'},
    )
    name_id.text = user_id

    subject_confirmation = etree.SubElement(
        subject,
        f'{NS_SAML}SubjectConfirmation',
        attrib={'Method': 'urn:oasis:names:tc:SAML:2.0:cm:bearer'},
    )
    etree.SubElement(
        subject_confirmation,
        f'{NS_SAML}SubjectConfirmationData',
        attrib={'Recipient': token_url, 'NotOnOrAfter': not_on_or_after},
    )

    conditions = etree.SubElement(
        assertion,
        f'{NS_SAML}Conditions',
        attrib={'NotBefore': not_before, 'NotOnOrAfter': not_on_or_after},
    )
    audience_restriction = etree.SubElement(conditions, f'{NS_SAML}AudienceRestriction')
    audience = etree.SubElement(audience_restriction, f'{NS_SAML}Audience')
    audience.text = audience_value

    authn_statement = etree.SubElement(
        assertion,
        f'{NS_SAML}AuthnStatement',
        attrib={
            'AuthnInstant': issue_instant,
            'SessionIndex': assertion_id,
        },
    )
    authn_context = etree.SubElement(authn_statement, f'{NS_SAML}AuthnContext')
    authn_context_class_ref = etree.SubElement(authn_context, f'{NS_SAML}AuthnContextClassRef')
    authn_context_class_ref.text = SAML_AUTHN_CONTEXT_UNSPECIFIED

    return assertion


def generate_saml_assertion(
    client_id: str,
    user_id: str,
    audience: str,
    token_url: str,
    private_key_pem: str,
    private_key_passphrase: str = None,
    validity_minutes: int = 10,
) -> str:
    """
    Construct and digitally sign a SAML 2.0 XML assertion for SAP SuccessFactors.

    Args:
        client_id: The OAuth client ID (Issuer).
        user_id: The API user identifier (Subject NameID).
        audience: The SAML audience restriction value expected by SAP SuccessFactors.
        token_url: The OAuth token endpoint URL that receives the bearer assertion.
        private_key_pem: PEM-encoded RSA private key string used for signing.
        private_key_passphrase: Optional passphrase for the encrypted private key.
        validity_minutes: Duration in minutes for which the assertion is valid.

    Returns:
        str: Signed SAML 2.0 XML assertion string.

    Raises:
        InvalidPrivateKeyError: If the private key is malformed, unparseable, or invalid.
        SAMLAssertionGenerationError: If assertion building or signing fails.
    """
    passphrase_bytes = _load_rsa_private_key(private_key_pem, private_key_passphrase)

    now = datetime.now(timezone.utc)
    issue_instant = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    not_before = (now - timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    not_on_or_after = (now + timedelta(minutes=validity_minutes)).strftime('%Y-%m-%dT%H:%M:%SZ')
    assertion_id = f'_{uuid.uuid4()}'

    assertion = _build_saml_assertion(
        client_id, user_id, audience, token_url, issue_instant, not_before, not_on_or_after, assertion_id,
    )

    try:
        signer = signxml.XMLSigner(
            method=signxml.methods.enveloped,
            signature_algorithm='rsa-sha256',
            digest_algorithm='sha256',
        )
        signed_assertion = signer.sign(
            assertion,
            key=private_key_pem.encode('utf-8'),
            passphrase=passphrase_bytes,
        )
        return etree.tostring(signed_assertion, encoding='utf-8').decode('utf-8')
    except Exception as exc:
        raise SAMLAssertionGenerationError(f'XML-DSig signing failed: {str(exc)}') from exc
