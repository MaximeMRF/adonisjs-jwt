# Kubernetes ServiceAccount tokens

Services running in a Kubernetes cluster can authenticate against your API with their ServiceAccount token, without any shared secret. The API server signs these tokens and publishes its public keys, so the guard can verify them in [JWKS](/guide/jwks) mode.

![The kubelet mounts a projected token in the client pod, which sends it to the AdonisJS API. The guard verifies it with the API server's public keys. A default token is rejected with a 401.](/k8s-architecture.png)

## Configure the guard

The Kubernetes API server exposes its signing keys at `https://kubernetes.default.svc/openid/v1/jwks`. From inside the cluster, fetching them requires the cluster CA and a ServiceAccount token, which you can provide with a custom `jwks-rsa` `fetcher`. The token is read again on each fetch because projected tokens are rotated:

```ts
import { readFileSync } from 'node:fs'
import https from 'node:https'

const SA_DIR = '/var/run/secrets/kubernetes.io/serviceaccount'

jwtGuard({
  // findById receives the token `sub`, e.g. "system:serviceaccount:my-namespace:my-sa"
  provider: new ServiceAccountUserProvider(),
  jwks: {
    jwksUri: 'https://kubernetes.default.svc/openid/v1/jwks',
    cache: true,
    fetcher: (uri) =>
      new Promise((resolve, reject) => {
        https
          .get(
            uri,
            {
              ca: readFileSync(`${SA_DIR}/ca.crt`),
              headers: { Authorization: `Bearer ${readFileSync(`${SA_DIR}/token`, 'utf8')}` },
            },
            (res) => {
              let body = ''
              res.on('data', (chunk) => (body += chunk))
              res.on('end', () => {
                if (res.statusCode !== 200) {
                  return reject(new Error(`JWKS fetch failed with status ${res.statusCode}`))
                }
                resolve(JSON.parse(body))
              })
            }
          )
          .on('error', reject)
      }),
  },
  // must match the `audience` of the projected token mounted in the calling pods
  audience: 'my-api',
  // default issuer on kubeadm-based clusters, managed clusters use their own URL
  issuer: 'https://kubernetes.default.svc.cluster.local',
  getUserId: (payload) => payload.sub,
})
```

`ServiceAccountUserProvider` is your own [user provider](/reference/guard#user-provider): its `findById` receives the `sub` claim and returns the matching service, or `null` to reject it.

::: warning
Always set `audience`. Without it, every pod's default ServiceAccount token would be accepted.
:::

## Find the issuer

The issuer depends on your cluster. `https://kubernetes.default.svc.cluster.local` is the kubeadm default, while managed clusters use their own URL, e.g. `https://oidc.eks.<region>.amazonaws.com/id/<id>` on EKS or `https://container.googleapis.com/v1/projects/<project>/locations/<location>/clusters/<cluster>` on GKE. Check yours with:

```sh
kubectl get --raw /.well-known/openid-configuration
```

Legacy Secret-based ServiceAccount tokens (issuer `kubernetes/serviceaccount`, no expiration) are rejected by the `issuer` check.

## Send the token from a pod

The calling pod mounts a projected token with your API as audience:

```yaml
spec:
  containers:
    - name: my-client
      volumeMounts:
        - name: api-token
          mountPath: /var/run/secrets/my-api
          readOnly: true
  volumes:
    - name: api-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              audience: my-api
              expirationSeconds: 3600
```

and sends it as a bearer token:

```ts
import { readFile } from 'node:fs/promises'

const token = await readFile('/var/run/secrets/my-api/token', 'utf8')
await fetch('http://my-api/jobs', {
  headers: { Authorization: `Bearer ${token}` },
})
```

The kubelet rotates this token before it expires, so the client must read the file again on each request, or at least regularly, instead of caching it at startup.

::: info Revocation
Tokens are verified offline against the JWKS, not through the Kubernetes `TokenReview` API. A token stays valid until its `exp` even if the pod it was issued for has been deleted (up to `expirationSeconds`, minimum 600). Keep `expirationSeconds` short, or call `TokenReview` from your user provider if you need immediate revocation.
:::

## What it protects against, and what it doesn't

ServiceAccount tokens remove the shared secret between your services. There's no API key to leak from an environment variable or a Git repository, and no one can forge an identity without the cluster's signing key. The audience also works both ways: a token for `my-api` is rejected by the Kubernetes API server, so a compromised API can't reuse the tokens it receives to drive the cluster.

The security boundary becomes Kubernetes RBAC, and a few things stay your job:

- **A compromised pod is that service.** An attacker inside a client pod reads its token and calls your API as that ServiceAccount for as long as they stay in the pod. Authorize per service, so each ServiceAccount can only call the routes it needs.
- **Whoever can get a token is that service.** Creating pods in the caller's namespace, `exec` into its pods, or the `create serviceaccounts/token` permission all give its token. Keep those rights tight.
- **The bearer token travels over plain HTTP.** Anyone who can sniff the cluster's traffic sees it. Use TLS, or a service mesh with mTLS, if that's in your threat model.
- **Keep internal routes internal.** Don't expose them through your ingress, and restrict who can reach the API with a NetworkPolicy. Your CNI has to enforce it.
- **Never turn off TLS verification on the JWKS fetch.** The keys are public, but someone in the middle could serve their own and sign any token.

You don't need an API key on top: it would bring back a secret to manage without closing any of these gaps.
