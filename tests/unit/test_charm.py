# Copyright 2023 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest

import ops
import ops.testing
from charm import MulticertCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = ops.testing.Harness(MulticertCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin_with_initial_hooks()

    def test_config_changed(self):
        # Trigger a config-changed event with an updated value
        self.harness.update_config({"cert-subjects": "subj1,subj2"})

    def test_certs_relation(self):
        relation_id = self.harness.add_relation("certificates", "ca")
        self.harness.add_relation_unit(relation_id, "ca/0")

    def test_certs_relation_with_config(self):
        relation_id = self.harness.add_relation("certificates", "ca")
        self.harness.add_relation_unit(relation_id, "ca/0")
        self.harness.update_config({"cert-subjects": "subj1,subj2"})
