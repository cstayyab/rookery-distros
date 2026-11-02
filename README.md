# rookery-distros

The list of Linux distributions that [Rookery](https://github.com/cstayyab) offers to install.

`manifest.json` holds, for each distribution and Android ABI, the URL of the official rootfs
image and its SHA-256. It never holds the images themselves: Rookery downloads them straight
from each distribution's own servers.

| Distribution | Source |
| --- | --- |
| Alpine Linux | `alpine-minirootfs` from dl-cdn.alpinelinux.org |
| Debian | The official Docker rootfs built by [debuerreotype](https://github.com/debuerreotype/docker-debian-artifacts), pinned to a commit |
| Ubuntu | Ubuntu Base from cdimage.ubuntu.com |

## Signature

`manifest.json.sig` is an Ed25519 signature (base64) over the exact bytes of `manifest.json`.
Rookery has the key in `public-key.txt` built in. It checks the signature before it reads the
manifest, and the SHA-256 of every image before it unpacks it. It also refuses a manifest whose
`serial` is lower than one it has already seen.

## Updating

Upstream images change: Alpine and Ubuntu publish point releases, and Debian's artifact branch
is rebuilt about once a month. Refresh, sign and push:

```sh
uv run tools/manifest.py update
uv run tools/manifest.py sign path/to/manifest-signing-key.pem
git commit -am "chore: refresh images" && git push
```

The signing key never goes in this repository.

## Licence

The manifest and tools are released under the MIT licence. The distributions are under their own licences.
