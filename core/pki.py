"""
Infrastruttura PKI istituzionale
"""


import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

from crypto_utils import generate_rsa_keypair

CA_KEY_SIZE = 4096

#impone uso standard RSA-PSS per la firma dei certificati X.509v3
def _x509_pss_padding():
    return asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA256()),
        salt_length=hashes.SHA256().digest_size,
    )

#crea un oggetto x509.Name con i campi standard per l'Ateneo
def _make_subject(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universita degli Studi di Salerno"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

#Verifica un singolo passaggio della catena: che 'cert' sia stato davvero firmato da issuer_public_key, e che sia temporalmente valido.
def _verify_certificate_signature(issuer_public_key, cert: x509.Certificate) -> bool:

    try:
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            _x509_pss_padding(),
            cert.signature_hash_algorithm,
        )
        now = datetime.datetime.utcnow()
        not_before = cert.not_valid_before_utc.replace(tzinfo=None)
        not_after = cert.not_valid_after_utc.replace(tzinfo=None)
        return not_before <= now <= not_after
    except Exception:
        return False

 #Root CA istituzionale dell'Ateneo (WP1 §1.3.1). Non firma mai
    #direttamente i certificati end-entity: crea una o piu' CA Intermedie,
    #che firmano i certificati di AA e GU.
class RootCA:

    def __init__(self, common_name="Universita degli Studi di Salerno Root CA"):
        self.private_key, self.public_key = generate_rsa_keypair(key_size=CA_KEY_SIZE)
        subject = issuer = _make_subject(common_name)
        now = datetime.datetime.utcnow()
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.private_key, hashes.SHA256(), rsa_padding=_x509_pss_padding())
        )
    #Crea una CA Intermedia firmata da questa Root.
    def create_intermediate(self, common_name="Universita degli Studi di Salerno Intermediate CA"):
    
        return IntermediateCA(self, common_name)

    """Verifica la catena di fiducia fino alla Root CA. Se viene
    fornito 'intermediate_cert', verifica entrambi i passaggi
    (Root->Intermedia e Intermedia->cert); altrimenti verifica
    'cert' come firmato direttamente dalla Root."""
    def verify_chain(self, cert: x509.Certificate, intermediate_cert: x509.Certificate = None) -> bool:
        if intermediate_cert is not None:
            if not _verify_certificate_signature(self.public_key, intermediate_cert):
                return False
            return _verify_certificate_signature(intermediate_cert.public_key(), cert)
        return _verify_certificate_signature(self.public_key, cert)

#CA Intermedia: firma i certificati end-entity (AA, GU) per conto
   # della Root. Se la sua chiave venisse compromessa, la si puo' revocare
    #e sostituire senza dover toccare la Root.
class IntermediateCA:

    def __init__(self, root_ca: RootCA, common_name: str):
        self.root_ca = root_ca
        self.private_key, self.public_key = generate_rsa_keypair(key_size=CA_KEY_SIZE)
        subject = _make_subject(common_name)
        now = datetime.datetime.utcnow()
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(root_ca.certificate.subject)
            .public_key(self.public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1825))
            # path_length=0: puo' firmare certificati end-entity, ma non
            # puo' creare a sua volta altre CA (la Root ha path_length=None).
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(root_ca.private_key, hashes.SHA256(), rsa_padding=_x509_pss_padding())
        )


    #Emette un certificato X.509v3 end-entity (server TLS) firmato da questa CA Intermedia.
    def issue_server_certificate(self, common_name: str, days_valid: int = 365):
        server_sk, server_pk = generate_rsa_keypair()
        subject = _make_subject(common_name)
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.certificate.subject)
            .public_key(server_pk)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=days_valid))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=True,
                    content_commitment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(self.private_key, hashes.SHA256(), rsa_padding=_x509_pss_padding())
        )
        return server_sk, server_pk, cert
