from cryptography.hazmat._oid import ExtendedKeyUsageOID, AuthorityInformationAccessOID
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
import random, ipaddress
from cryptography.x509.oid import NameOID
from cryptography import x509

def generate_random_ext(oid: ObjectIdentifier) -> x509.Extension:
    # Generate random extension based on different OIDs
    if oid == ExtensionOID.BASIC_CONSTRAINTS:
        return x509.Extension(
            oid=oid,
            critical=random.choice([True, False]),
            value=x509.BasicConstraints(
                ca=random.choice([True, False]),
                path_length=random.randint(0, 10) if random.random() > 0.5 else None
            )
        )

    elif oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
        names = []
        # Randomly generate 1-5 SAN entries
        for _ in range(random.randint(1, 5)):
            name_type = random.choice(["dns", "ip", "email", "uri"])
            if name_type == "dns":
                names.append(x509.DNSName(f"rand-domain-{random.randint(1, 1000)}.com"))
            elif name_type == "ip":
                names.append(x509.IPAddress(ipaddress.ip_address(
                    f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
                )))
            elif name_type == "email":
                names.append(x509.RFC822Name(f"user{random.randint(1, 100)}@example.com"))
            elif name_type == "uri":
                names.append(x509.UniformResourceIdentifier(
                    f"https://example.com/resource/{random.randint(1000, 9999)}"
                ))
        return x509.Extension(
            oid=oid,
            critical=random.choice([True, False]),
            value=x509.SubjectAlternativeName(names)
        )

    elif oid == ExtensionOID.KEY_USAGE:
        return x509.Extension(
            oid=oid,
            critical=True,
            value=x509.KeyUsage(
                digital_signature=random.choice([True, False]),
                content_commitment=random.choice([True, False]),
                key_encipherment=random.choice([True, False]),
                data_encipherment=random.choice([True, False]),
                key_agreement=random.choice([True, False]),
                key_cert_sign=random.choice([True, False]),
                crl_sign=random.choice([True, False]),
                encipher_only=random.choice([True, False]) if random.random() > 0.8 else False,
                decipher_only=random.choice([True, False]) if random.random() > 0.8 else False
            )
        )

    elif oid == ExtensionOID.EXTENDED_KEY_USAGE:
        # Randomly select 1-5 EKU usages
        ekus = random.sample([
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
            ExtendedKeyUsageOID.CODE_SIGNING,
            ExtendedKeyUsageOID.EMAIL_PROTECTION,
            ExtendedKeyUsageOID.TIME_STAMPING,
            ExtendedKeyUsageOID.OCSP_SIGNING,
            ObjectIdentifier("1.3.6.1.5.5.7.3.9"),
            ObjectIdentifier("1.3.6.1.5.5.7.3.21"),
        ], k=random.randint(1, 5))
        return x509.Extension(
            oid=oid,
            critical=random.choice([True, False]),
            value=x509.ExtendedKeyUsage(ekus)
        )

    elif oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
        # Randomly generate 20-byte key identifier
        return x509.Extension(
            oid=oid,
            critical=False,
            value=x509.SubjectKeyIdentifier(bytes([random.randint(0, 255) for _ in range(20)]))
        )

    elif oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
        # Randomly generate authority key identifier
        key_id = bytes([random.randint(0, 255) for _ in range(20)])
        # 50% chance to include issuer information
        if random.random() > 0.5:
            issuer = None
        else:
            # Randomly create DN
            issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, random.choice(["US", "CN", "GB", "DE"])),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"Random Org {random.randint(1, 100)}"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"Random CA {random.randint(1, 100)}"),
            ])
        # 50% chance to include serial number
        serial = random.randint(1, 2 ** 64 - 1) if random.random() > 0.5 else None

        return x509.Extension(
            oid=oid,
            critical=False,
            value=x509.AuthorityKeyIdentifier(key_id, [issuer] if issuer else None, serial)
        )

    elif oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
        descriptions = []
        # Randomly generate 1-3 access descriptions
        for _ in range(random.randint(1, 3)):
            method = random.choice([
                AuthorityInformationAccessOID.OCSP,
                AuthorityInformationAccessOID.CA_ISSUERS
            ])
            location = x509.UniformResourceIdentifier(
                f"https://{'ocsp' if method == AuthorityInformationAccessOID.OCSP else 'ca'}.example.com/path/{random.randint(1000, 9999)}"
            )
            descriptions.append(x509.AccessDescription(method, location))

        return x509.Extension(
            oid=oid,
            critical=False,
            value=x509.AuthorityInformationAccess(descriptions)
        )

    elif oid == ExtensionOID.CERTIFICATE_POLICIES:
        policies = []
        # Randomly generate 1-3 certificate policies
        for _ in range(random.randint(1, 3)):
            policy_id = ObjectIdentifier(f"1.3.6.1.4.1.{random.randint(1000, 9999)}.{random.randint(1, 100)}")
            # 30% chance to add policy qualifiers
            qualifiers = []
            if random.random() > 0.7:
                # Add CPS qualifier
                qualifiers.append(x509.CPSQualifier(
                    f"https://cps.example.com/policy/{random.randint(100, 999)}"
                ))
            if random.random() > 0.7:
                # Add user notice qualifier
                qualifiers.append(x509.UserNotice(
                    notice_reference=x509.NoticeReference(
                        organization=f"Policy Org {random.randint(1, 10)}",
                        notice_numbers=[random.randint(1, 100) for _ in range(3)]
                    ),
                    explicit_text=f"Random policy notice {random.randint(1, 100)}" if random.random() > 0.5 else None
                ))
            policies.append(x509.PolicyInformation(policy_id, qualifiers))

        return x509.Extension(
            oid=oid,
            critical=random.choice([True, False]),
            value=x509.CertificatePolicies(policies)
        )

    elif oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
        distribution_points = []
        # Randomly generate 1-3 CRL distribution points
        for _ in range(random.randint(1, 3)):
            # Create distribution point name
            name = x509.UniformResourceIdentifier(
                f"https://crl.example.com/{random.randint(1000, 9999)}.crl"
            )
            # Randomly add reasons and CRL issuer
            reasons = None
            if random.random() > 0.7:
                reasons = frozenset(random.sample([
                    x509.ReasonFlags.key_compromise,
                    x509.ReasonFlags.ca_compromise,
                    x509.ReasonFlags.affiliation_changed,
                    x509.ReasonFlags.superseded,
                    x509.ReasonFlags.cessation_of_operation,
                    x509.ReasonFlags.certificate_hold,
                    x509.ReasonFlags.privilege_withdrawn,
                    x509.ReasonFlags.aa_compromise
                ], k=random.randint(1, 3)))

            crl_issuer = None
            if random.random() > 0.7:
                crl_issuer = [x509.DirectoryName(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, f"CRL Issuer {random.randint(1, 100)}")
                ]))]

            distribution_points.append(x509.DistributionPoint(
                full_name=[name],
                relative_name=None,
                reasons=reasons,
                crl_issuer=crl_issuer
            ))

        return x509.Extension(
            oid=oid,
            critical=random.choice([True, False]),
            value=x509.CRLDistributionPoints(distribution_points)
        )

    elif oid == ExtensionOID.FRESHEST_CRL:
        # Freshest CRL distribution points (similar to CRL distribution points but for Delta CRL)
        distribution_points = []
        for _ in range(random.randint(1, 2)):
            name = x509.UniformResourceIdentifier(
                f"https://delta-crl.example.com/{random.randint(1000, 9999)}.crl"
            )
            distribution_points.append(x509.DistributionPoint(
                full_name=[name],
                relative_name=None,
                reasons=None,
                crl_issuer=None
            ))

        return x509.Extension(
            oid=oid,
            critical=random.choice([True, False]),
            value=x509.FreshestCRL(distribution_points)
        )

    elif oid == ExtensionOID.ISSUER_ALTERNATIVE_NAME:
        names = []
        # Randomly generate 1-3 issuer alternative names
        for _ in range(random.randint(1, 3)):
            name_type = random.choice(["dns", "email", "uri"])
            if name_type == "dns":
                names.append(x509.DNSName(f"ca-domain-{random.randint(1, 100)}.com"))
            elif name_type == "email":
                names.append(x509.RFC822Name(f"admin{random.randint(1, 100)}@ca.example.com"))
            elif name_type == "uri":
                names.append(x509.UniformResourceIdentifier(
                    f"https://ca.example.com/info/{random.randint(1000, 9999)}"
                ))
        return x509.Extension(
            oid=oid,
            critical=random.choice([True, False]),
            value=x509.IssuerAlternativeName(names)
        )

    elif oid == ExtensionOID.NAME_CONSTRAINTS:
        # Name constraints extension
        permitted = [x509.DNSName(f"domain{random.randint(1, 10)}.com")]
        excluded = [x509.DNSName(f"forbidden.domain{random.randint(1, 10)}.com")] if random.random() > 0.5 else None

        return x509.Extension(
            oid=oid,
            critical=True,
            value=x509.NameConstraints(
                permitted_subtrees=permitted,
                excluded_subtrees=excluded
            )
        )

    elif oid == ExtensionOID.POLICY_CONSTRAINTS:
        # Policy constraints extension
        require_explicit_policy = random.randint(0, 5) if random.random() > 0.5 else None
        inhibit_policy_mapping = random.randint(0, 5) if random.random() > 0.5 else None

        return x509.Extension(
            oid=oid,
            critical=True,
            value=x509.PolicyConstraints(
                require_explicit_policy=require_explicit_policy,
                inhibit_policy_mapping=inhibit_policy_mapping
            )
        )

    elif oid == ExtensionOID.POLICY_MAPPINGS:
        # Policy mappings extension
        mappings = []
        for _ in range(random.randint(1, 3)):
            issuer_policy = ObjectIdentifier(f"1.3.6.1.4.1.{random.randint(10000, 99999)}")
            subject_policy = ObjectIdentifier(f"1.3.6.1.4.1.{random.randint(10000, 99999)}")
            mappings.append(x509.PolicyMapping(issuer_policy, subject_policy))

        return x509.Extension(
            oid=oid,
            critical=random.choice([True, False]),
            value=x509.PolicyMappings(mappings)
        )

    elif oid == ExtensionOID.INHIBIT_ANY_POLICY:
        # Inhibit any policy extension
        return x509.Extension(
            oid=oid,
            critical=True,
            value=x509.InhibitAnyPolicy(skip_certs=random.randint(0, 10))
        )

    elif oid == ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES:
        # Subject directory attributes extension (rarely used)
        attributes = []
        for _ in range(random.randint(1, 3)):
            attr_type = ObjectIdentifier(f"1.2.3.4.5.{random.randint(10000, 99999)}")
            attr_value = bytes([random.randint(0, 255) for _ in range(10)])
            attributes.append(x509.Attribute(attr_type, [attr_value]))

        return x509.Extension(
            oid=oid,
            critical=random.choice([True, False]),
            value=x509.SubjectDirectoryAttributes(attributes)
        )

    # Other standard extensions
    else:
        # For unknown or unsupported OIDs, generate unrecognized extension
        # Generate random data of 10-50 bytes
        ext_length = random.randint(10, 50)
        return x509.Extension(
            oid=oid,
            critical=random.choice([True, False]),
            value=x509.UnrecognizedExtension(
                oid=oid,
                value=bytes([random.randint(0, 255) for _ in range(ext_length)])
            )
        )


# Main certificate processing function
def process_cert(cert_data: bytes, extensions_oids: set) -> x509.Certificate:
    # Load original certificate
    orig_cert = x509.load_der_x509_certificate(cert_data)

    # Create certificate builder and clone basic fields
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(orig_cert.serial_number)
    builder = builder.issuer_name(orig_cert.issuer)
    builder = builder.subject_name(orig_cert.subject)
    builder = builder.not_valid_before(orig_cert.not_valid_before)
    builder = builder.not_valid_after(orig_cert.not_valid_after)
    builder = builder.public_key(orig_cert.public_key())

    # Copy original extensions and update OID set
    for ext in orig_cert.extensions:
        builder = builder.add_extension(ext.value, critical=ext.critical)
        if ext.oid in extensions_oids:
            extensions_oids.remove(ext.oid)

    # Randomly select and generate missing extensions
    selected_oids = random.sample(
        list(extensions_oids),
        k=min(5, len(extensions_oids))  # Add up to 5 new extensions
    )

    for oid in selected_oids:
        try:
            new_ext = generate_random_ext(oid)
            builder = builder.add_extension(
                new_ext.value,
                critical=new_ext.critical
            )
        except Exception as e:
            print(f"Error generating extension {oid}: {str(e)}")

    # Generate temporary key for signing (for testing)
    temp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build and return new certificate
    return builder.sign(
        private_key=temp_key,
        algorithm=hashes.SHA256(),
    )


# Usage example
if __name__ == "__main__":
    # Sample certificate data (should be read from file in practice)
    with open("./www.wosign.com.der", "rb") as f:
        cert_data = f.read()

    # Define set of extension OIDs to cover
    required_extensions = {
        ExtensionOID.BASIC_CONSTRAINTS,
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        ExtensionOID.KEY_USAGE,
        ExtensionOID.EXTENDED_KEY_USAGE,
        ExtensionOID.CRL_DISTRIBUTION_POINTS,
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
        ExtensionOID.SUBJECT_KEY_IDENTIFIER,
        ExtensionOID.CERTIFICATE_POLICIES,
        ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
        ExtensionOID.ISSUER_ALTERNATIVE_NAME,
        ExtensionOID.NAME_CONSTRAINTS,
        ExtensionOID.POLICY_CONSTRAINTS,
        ExtensionOID.POLICY_MAPPINGS,
        ExtensionOID.INHIBIT_ANY_POLICY,
        ExtensionOID.FRESHEST_CRL,
        ObjectIdentifier("2.5.29.36"),
        ObjectIdentifier("2.5.29.37"),
    }
    # Process certificate and output
    new_cert = process_cert(cert_data, required_extensions.copy())
    # Save as DER format to current directory
    der_filename = f"cert_with_extensions.der"
    with open(der_filename, "wb") as der_file:
        der_file.write(new_cert.public_bytes(serialization.Encoding.DER))

    print(f"Generated new certificate saved as: {der_filename}")
    print(f"Contains {len(new_cert.extensions)} extensions")