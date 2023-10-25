#!/usr/bin/env python3
# Copyright 2023 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm the service.

Refer to the following tutorial that will help you
develop a new k8s charm using the Operator Framework:

https://juju.is/docs/sdk/create-a-minimal-kubernetes-charm
"""

import ipaddress
import json
import logging
import socket
from itertools import filterfalse
from typing import List, MutableMapping, Optional

import ops
from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore
    # AllCertificatesInvalidatedEvent,
    # CertificateAvailableEvent,
    # CertificateExpiringEvent,
    # CertificateInvalidatedEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)


def is_ip_address(value: str) -> bool:
    """Return True if the input value is a valid IPv4 address; False otherwise."""
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


class MulticertCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)
        self.certificates = TLSCertificatesRequiresV2(self, "certificates")

        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on["peers"].relation_created, self._on_peer_relation_created)
        self.framework.observe(self.on["peers"].relation_joined, self._on_peer_relation_joined)

    def _on_config_changed(self, event: ops.ConfigChangedEvent):
        """Handle changed configuration.

        Change this example to suit your needs. If you don't need to handle config, you can remove
        this method.

        Learn more about config at https://juju.is/docs/sdk/config
        """
        # Assuming the peer relation is already in place by the time config-changed is emitted.
        self._commit_cert_subjects()

    def _on_peer_relation_joined(self, event):
        self._commit_cert_subjects()

    def _on_peer_relation_created(self, event):
        if not self._private_key:
            private_key = generate_private_key()
            self._private_key = private_key.decode()

    @property
    def _peer_data(self) -> Optional[MutableMapping]:
        if peer_relation := self.model.get_relation("peers", None):
            return peer_relation.data[self.unit]
        return None

    def _commit_cert_subjects(self):
        if not self.certs_enabled:
            return

        # This method may be called before peer relation created, so must guard against it, relying
        # on the fact that it will be called from all relevant hooks, so eventually this code will
        # run.

        # Assuming the peer relation is already in place by the time config-changed is emitted.
        peer_data = self._peer_data
        assert peer_data is not None

        # The config option may be unset
        if cert_subjects := self.model.config["cert-subjects"]:
            # Charm may be scaled up, and we want each unit to render its own CSRs
            per_unit_cert_names = {
                f"{self.unit.name.replace('/', '-')}-{subj}" for subj in cert_subjects.split(",")
            }
        else:
            per_unit_cert_names = {}

        # Compare the (potentially new) cert subjects to what's already there.
        # Stale subjects need to be revoked and new subjects need to be requested.
        old_subjects = set(json.loads(peer_data.get("requested_subjects", "[]")))
        stale_subjects = old_subjects.difference(per_unit_cert_names)
        new_subjects = per_unit_cert_names.difference(old_subjects)

        csr_map = {}
        for subj in new_subjects:
            csr = self.request_csr(cert_subject=subj, sans=[f"{subj}.{socket.getfqdn()}"])
            # Revocation operates on csrs, so in order to be able to send a revocation request in
            # the future, we need a mapping between the subject and the csr.
            csr_map[subj] = csr.decode().strip()

        prev_csr_map = json.loads(peer_data.get("csr_map", "{}"))
        for subj in stale_subjects:
            csr = prev_csr_map[subj]
            self.certificates.request_certificate_revocation(csr.encode())
            prev_csr_map.pop(subj)

        # Update peer data.
        # TODO serialize using pydantic
        peer_data.update({"requested_subjects": json.dumps(list(per_unit_cert_names))})
        peer_data.update({"csr_map": json.dumps({**prev_csr_map, **csr_map})})

    @property
    def certs_enabled(self) -> bool:
        """Boolean indicating whether the charm has a tls_certificates relation."""
        # We need to check for units as a temporary workaround because of https://bugs.launchpad.net/juju/+bug/2024583
        # This could in theory not work correctly on scale down to 0 but it is necessary for the moment.
        return (
            len(self.model.relations["certificates"]) > 0
            and len(self.model.get_relation("certificates").units) > 0  # type: ignore
        )

    def _redner_csr(self, *, cert_subject: str, sans: List[str]) -> bytes:
        """Generate CSR.

        Args:
            cert_subject: Custom subject. Name collisions are under the caller's responsibility.
            sans: DNS names. If none are given, use FQDN.
        """
        # Use fqdn only if no SANs were given, and drop empty/duplicate SANs
        sans = list(set(filter(None, (sans or [socket.getfqdn()]))))
        sans_ip = list(filter(is_ip_address, sans))
        sans_dns = list(filterfalse(is_ip_address, sans))

        private_key = self._private_key
        assert private_key is not None  # for type checker
        return generate_csr(
            private_key=private_key.encode(),
            subject=cert_subject,
            sans_dns=sans_dns,
            sans_ip=sans_ip,
        )

    def request_csr(self, *, cert_subject: str, sans: List[str]) -> bytes:
        """Assuming cert_subject is unique (caller's responsibility)."""
        csr = self._redner_csr(cert_subject=cert_subject, sans=sans)

        logger.info(
            "Requesting new CSR for %s with SANs %s",
            cert_subject,
            sans,
        )
        self.certificates.request_certificate_creation(certificate_signing_request=csr)
        return csr

    @property
    def _private_key(self) -> Optional[str]:
        if peer_data := self._peer_data:
            return peer_data.get("private_key", None)
        return None

    @_private_key.setter
    def _private_key(self, value: str):
        # Caller must guard. We want the setter to fail loudly. Failure must have a side effect.
        peer_data = self._peer_data
        assert peer_data is not None  # For type checker
        peer_data.update({"private_key": value})


if __name__ == "__main__":  # pragma: nocover
    ops.main(MulticertCharm)  # type: ignore
