# Licensing

Work within the Serai project _MUST_ be licensed in a way allowing
(conditional) redistribution, allow (conditionally) creating derived works, and
_MUST NOT_ discriminate against any specific entities or usages, as akin to the
[open source initiative's Open Source Definition](https://opensource.org/osd).
An OSI-approved license is _NOT_ explicitly required solely due it limiting
itself to source code, while work within the Serai project is not solely in the
form of source code. In practice, work within the Serai project _MUST_ be
either licensed under an OSI-approved license _or_ an approximate
[Creative Commons](https://creativecommons.org/) license (even though the
[OSI does not consider the CC0 license to be open source](
  https://opensource.org/faq#cc-zero
)).

Code within and original to the Serai project is generally licensed under one
of two licenses, either the MIT license or the AGPL-3.0-only license. The
former is preferred for _libraries_ where external consumption is intended. The
latter is preferred for _projects_ which exist to instantiate the Serai network
and whose alternative usage would presumably be to create a derivative of the
Serai project itself, in order to increase the likelihood of reciprocity.

Media is generally licensed under a
[Creative Commons](https://creativecommons.org/) license, with
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) preferred.
The maintainers of Serai have not filed for any trademarks or patents for Serai
nor the technology within. The maintainers of Serai are unaware of any
encumberance by patents over any of the technology contained within it.

A copy of the
[AGPL-3.0 license is included in the root of this repository](/AGPL-3.0).
This full text should be provided with any distribution of any portion/derivative
of Serai licensed under the AGPL-3.0, as per its terms.

A copy of the
[CC BY-SA 4.0 is included in the root of this repository](/CC BY-SA 4.0) for
clarity and to avoid reliance on an external web server. The creators of
"Licensed Material" (licensed under the CC BY-SA 4.0) are requested to be
attributed as "Serai Contributors".

### Specification of License

Each portion of the Serai codebase (such as a "crate", in Rust terminology, but
generally as organized within a folder) is expected to declare its license
within its manifest and within its folder. For portions of the Serai codebase
which may be _nested_ within each other, such as seen with
`coordinator/tributary-sdk/tendermint`, the associated license is expected to
be the one of closest proximity
(e.g. `coordinator/LICENSE` is not expected to cover
`coordinator/tributary-sdk/tendermint` as
`coordinator/tributary-sdk/tendermint/LICENSE` exists and is immediate to
`coordinator/tributary-sdk/tendermint`).

If any files are of unclear licensing terms, or incorrectly licensed, please
reach out as this is considered an error to be immediately corrected.

### Contributions

Copyright over the contributions made to the Serai project remain with the
copyright holder. For acknowledgement within the copyright statement,
"Serai Contributors" is generally used and preferred. In order to ensure
contributions are appropriately credited and licensed, a
[Developer Certificate of Origin](https://developercertificate.org)
Version 1.1 must be submitted along with contributions. Its text (and its own
acknowledgement of its copyright/licensing) is included as follows:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

The following additional statement (which is not part of the above, per its
requirement it isn't modified) must also be included:

```
No output from a Large Language Model (LLM) was included within any of the
contribution.
```

Serai, as a project, considers this to be clarifying regarding the
Developer's Certificate of Origin 1.1's clause (b), which states the
contribution (if based upon previous work) is appropriately licensed and grants
the contributor the right to submit and license the work contributed. At this
time, no Large Language Model preserves attribution throughout its stack and
it's unclear how its derivations will be legally interpreted. In response, the
Serai project (which is not composed of lawyers and offers no legal advice) has
adopted the conservative stance no such outputs are to be considered as
appropriately licensed.

This additional statement also stands on ethical grounds where regardless of
legal right, FOSS licenses establish developers' requests for how their work
is used, whether requiring acknowledgement or that derivatives are reciprocated
in kind. Even if ignoring these requests is legal, that does not excuse the
disrespect shown to those whose work was _required_ to enable the Large
Language Model to function.

This additional statement also stands on technical grounds where the outputs of
Large Language Models are frequently inaccurate/low quality, yet mask
themselves as reasonable quality via their presentation, hindering fair
analysis, harming the contibutor/reviewer process to effect a quality codebase,
and potentially overwhelming reviewers due to the volume they're capable of
outputting (without the expected quality).

### Top-Level Files

- `.gitattributes`
- `.rustfmt.toml`
- `rust-toolchain.toml`

are licensed as follows:

```
MIT License

Copyright (c) 2021-2026 Serai Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- `.gitignore`
- `Cargo.lock`
- `Cargo.toml`
- `clippy.toml`
- `deny.toml`

are licensed as follows:

```
AGPL-3.0-only license

Copyright (c) 2021-2026 Serai Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License Version 3 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
```

- `CONTRIBUTING.md`
- `LICENSE.md`
- `README.md`
- `SECURITY.md`

are licensed under the CC BY-SA 4.0 license.

- `AGPL-3.0`
- `CC BY-SA 4.0`
- `Code of Conduct.md`

declare their licensing terms within themselves.
