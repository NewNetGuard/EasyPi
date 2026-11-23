# Third-Party Licenses

EasyPi depends on third-party open-source software (for example: Linux, Debian/Raspberry Pi OS packages, Python libraries, Node.js libraries, Nginx, system tools, etc.).

Those components are licensed under their own terms (such as MIT, BSD, Apache-2.0, GPL, and others).  
Your use of those components must comply with their respective licenses.

EasyPi proprietary terms apply only to EasyPi-owned code/content and do not replace or override third-party license obligations.

## Runtime Adult-Domain Feed

The optional adult-domain feed used by Parental Controls is downloaded and
generated on the end user's EasyPi device. The generated domain database is not
part of the EasyPi source tree or release archive, and EasyPi does not claim
ownership of it.

Current reviewed source:

- **The Block List Project - Porn Block List**
- Homepage: <https://github.com/blocklistproject/Lists>
- Runtime source: <https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt>
- Repository license: Unlicense
- The generated source file currently declares MIT in its header. EasyPi
  preserves that header and the repository license alongside the local data and
  uses the more conservative notice handling.

No HaGeZi, Sinfonietta, or StevenBlack adult-domain data is included in or
downloaded by the current EasyPi adult-feed updater.

The exact repository license reviewed for this source is included at
`third_party/blocklists/blocklistproject-UNLICENSE.txt`. Runtime provenance,
hashes, the preserved source header, and a copy of the upstream license are
written next to the generated feed under `/opt/EasyPi/data/netprotection/`.
