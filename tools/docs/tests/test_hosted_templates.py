"""Security and isolation invariants of the hosted collector examples."""
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]


class HostedTemplateTests(unittest.TestCase):
    def test_kubernetes_uses_one_writer_tls_and_default_deny(self):
        docs = list(yaml.safe_load_all((ROOT / 'deploy/kubernetes/deployment.yaml').read_text()))
        by_kind = {item['kind']: item for item in docs}
        deployment = by_kind['Deployment']['spec']
        self.assertEqual(deployment['replicas'], 1)
        self.assertEqual(deployment['strategy']['type'], 'Recreate')
        pod = deployment['template']['spec']
        security = pod['securityContext']
        self.assertTrue(security['runAsNonRoot'])
        self.assertEqual((security['runAsUser'], security['runAsGroup'], security['fsGroup']), (1654, 1654, 1654))
        container = pod['containers'][0]
        env = {item['name']: item.get('value') for item in container['env']}
        self.assertEqual(env['BOWER_LISTEN_URL'], 'https://0.0.0.0:4319')
        self.assertEqual(env['BOWER_PRODUCER_SCOPES_FILE'], '/etc/bower/producer-scopes/scopes.json')
        self.assertEqual(env['ASPNETCORE_Kestrel__Certificates__Default__Path'], '/var/run/secrets/bower-tls/tls.crt')
        self.assertEqual(env['ASPNETCORE_Kestrel__Certificates__Default__KeyPath'], '/var/run/secrets/bower-tls/tls.key')
        self.assertEqual(container['readinessProbe']['httpGet']['scheme'], 'HTTPS')
        self.assertEqual(container['livenessProbe']['httpGet']['scheme'], 'HTTPS')
        self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])
        volumes = {item['name']: item for item in pod['volumes']}
        self.assertEqual(volumes['ingest-token']['secret']['defaultMode'], 0o440)
        self.assertEqual(volumes['tls']['secret']['defaultMode'], 0o440)
        self.assertEqual(volumes['temporary']['emptyDir']['sizeLimit'], '64Mi')
        self.assertTrue(any(item['name'] == 'temporary' and item['mountPath'] == '/tmp'
                            for item in container['volumeMounts']))
        self.assertEqual(by_kind['PersistentVolumeClaim']['spec']['accessModes'], ['ReadWriteOnce'])
        self.assertEqual(yaml.safe_load(by_kind['ConfigMap']['data']['scopes.json']), [])
        ingress = by_kind['NetworkPolicy']['spec']['ingress'][0]['from'][0]
        self.assertNotIn('namespaceSelector', ingress)
        self.assertEqual(ingress['podSelector']['matchLabels']['bower.io/producer'], 'true')

    def test_compose_restricts_host_exposure_and_mounts_credentials(self):
        model = yaml.safe_load((ROOT / 'deploy/docker/hosted/compose.yaml').read_text())
        collector = model['services']['bower']
        self.assertTrue(collector['read_only'])
        self.assertEqual(collector['user'], '1654:1654')
        self.assertIn('ALL', collector['cap_drop'])
        self.assertEqual(collector['ports'], ['127.0.0.1:4319:4319'])
        env = collector['environment']
        self.assertEqual(env['BOWER_LISTEN_URL'], 'https://0.0.0.0:4319')
        self.assertEqual(env['BOWER_AZURE_CREDENTIAL'], 'managed-identity')
        self.assertEqual(env['BOWER_INGEST_TOKEN_FILE'], '/run/bower/ingest-token')
        self.assertEqual(env['BOWER_PRODUCER_SCOPES_FILE'], '/run/bower/producer-scopes.json')
        self.assertNotIn('BOWER_INGEST_TOKEN', env)
        self.assertTrue(any(item.endswith(':/run/bower/tls-key.pem:ro') for item in collector['volumes']))
        self.assertTrue(any(item.endswith(':/run/bower/ingest-token:ro') for item in collector['volumes']))

    def test_web_app_defaults_to_private_scoped_identity_and_no_durable_storage_claim(self):
        root = ROOT / 'deploy/azure-webapp'
        template = (root / 'main.bicep').read_text()
        self.assertIn("publicNetworkAccess: 'Disabled'", template)
        self.assertIn('httpsOnly: true', template)
        self.assertIn("minTlsVersion: '1.2'", template)
        self.assertIn("ftpsState: 'Disabled'", template)
        self.assertIn("param producerScopesJson string = '[]'", template)
        self.assertIn("name: 'BOWER_PRODUCER_SCOPES_JSON', value: producerScopesJson", template)
        self.assertIn("name: 'WEBSITES_ENABLE_APP_SERVICE_STORAGE', value: 'false'", template)
        self.assertIn('privateLinkServiceId: app.id', template)
        self.assertIn('@Microsoft.KeyVault(SecretUri=', template)
        self.assertNotIn('BOWER_ALLOW_UNAUTHENTICATED_INGEST', template)
        # Queue loss needs an explicit opt-in: no default, only true allowed.
        self.assertIn('@allowed([true])\nparam acknowledgeEphemeralQueue bool\n', template)
        self.assertNotRegex(template, r'param acknowledgeEphemeralQueue bool\s*=')
        self.assertIn("name: 'BOWER_QUEUE_MAX_BYTES', value: string(queueMaxBytes)", template)
        self.assertIn('param queueMaxBytes int = 1073741824', template)
        for document in (root / 'README.md', ROOT / 'docs/deployment/hosted-collectors.md'):
            self.assertIn('acknowledgeEphemeralQueue=true', document.read_text())
        # The identity and its Key Vault grant exist before the site's first start.
        self.assertNotIn('SystemAssigned', template)
        self.assertIn('keyVaultReferenceIdentity: identity.id', template)
        self.assertIn('dependsOn: [tokenGrant, dcrGrant, registryGrant]', template)
        self.assertIn("name: 'BOWER_AZURE_CLIENT_ID', value: identity.properties.clientId", template)
        for module, expected_scope in (('dcr-role.bicep', 'scope: dcr'),
                                       ('secret-role.bicep', 'scope: secret'),
                                       ('acr-role.bicep', 'scope: registry')):
            self.assertIn(expected_scope, (root / 'modules' / module).read_text())


if __name__ == '__main__':
    unittest.main()
