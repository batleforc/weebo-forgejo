# Changelog
All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

- - -
## [v0.2.1](https://github.com/batleforc/weebo-forgejo/compare/365c3b6f8d88f5427339f9c6fe524b92e5278007..v0.2.1) - 2026-10-13
#### Continuous Integration
- publish through the kit's workflow; Debian 13 and Hummingbird images (kit v0.11.0) (#5) - ([365c3b6](https://github.com/batleforc/weebo-forgejo/commit/365c3b6f8d88f5427339f9c6fe524b92e5278007)) - Maxime, Claude Opus 5.5, Claude Opus 5.5, Claude Opus 5.5

- - -

## [v0.2.0](https://github.com/batleforc/weebo-forgejo/compare/14a2913c29f528ebb3a04fd1fd140c0698ee6f09..v0.2.0) - 2026-10-12
#### Features
- ![BREAKING](https://img.shields.io/badge/BREAKING-red) namespaced identities, ForgejoLocalInstance and watch scope (kit v0.10.1) (#4) - ([d160600](https://github.com/batleforc/weebo-forgejo/commit/d160600ab4106d02a9a5bebb730272eda28931e9)) - Maxime, Claude Opus 5.5, Claude Opus 5.5, Claude Opus 5.5, Claude Opus 5.5, Claude Opus 5.5
- Ajout des templates de projet - ([14a2913](https://github.com/batleforc/weebo-forgejo/commit/14a2913c29f528ebb3a04fd1fd140c0698ee6f09)) - Max Batleforc

- - -

## [v0.1.0](https://github.com/batleforc/weebo-forgejo/compare/1d177d4ccf1eb089008f8418e667633fcc833051..v0.1.0) - 2026-10-11
#### Features
- build on weebo-operator-kit v0.9.0 (library chart, shared tasks, reusable CI) (#2) - ([81addeb](https://github.com/batleforc/weebo-forgejo/commit/81addebe9d97bc8ce0212a0573787c0077a7a911)) - Maxime
- build on weebo-operator-kit v0.7.0 - ([d663f8c](https://github.com/batleforc/weebo-forgejo/commit/d663f8c10c5c0b50cd7df2706690fe95a8e68fb3)) - Max Batleforc, Claude Opus 5.5
- announce every error and state change as an Event (kit v0.4.0) - ([c74d0dd](https://github.com/batleforc/weebo-forgejo/commit/c74d0dd86f0c68b5c5fb3887fe45fadc19deb142)) - Max Batleforc, Claude Opus 5.5
- production hardening from the prod-readiness review - ([f1068da](https://github.com/batleforc/weebo-forgejo/commit/f1068da4205bc91d8fc1cf3bc83cf1d32313c371)) - Max Batleforc, Claude Opus 5.5
- enhance the doc - ([368d252](https://github.com/batleforc/weebo-forgejo/commit/368d252e3baf26fee9a77d2a6c159aa926768359)) - Max Batleforc
- deploy doc - ([56ef958](https://github.com/batleforc/weebo-forgejo/commit/56ef95801f80a8efe412d9b073ede6723693b705)) - Max Batleforc
- wip - ([1e12a77](https://github.com/batleforc/weebo-forgejo/commit/1e12a77d2231083fe0a382cb0385867663b7abdf)) - Max Batleforc
- Review code and fix output message - ([86ae553](https://github.com/batleforc/weebo-forgejo/commit/86ae553696634d62786d878dfd24d1f59924d158)) - Max Batleforc
- weebo-forgejo operator, milestones M0 to M5 - ([e956049](https://github.com/batleforc/weebo-forgejo/commit/e9560491103d1ca775194ef57e05bebe0dbb5c2f)) - Max Batleforc, Claude Opus 5.5 (1M context)
#### Bug Fixes
- (**metrics**) gateway metrics exported without a doubled suffix - ([e2adf31](https://github.com/batleforc/weebo-forgejo/commit/e2adf314e10b72b80bd6f1e22bf26c406ab0f28d)) - Max Batleforc, Claude Opus 5.5
- address full-codebase review findings - ([95faa2d](https://github.com/batleforc/weebo-forgejo/commit/95faa2d691d50055e9b5c82393ec5350c418d571)) - Max Batleforc, Claude Opus 5.5 (1M context)
- repository-limited token scopes and e2e/audit findings from first CI run - ([1804515](https://github.com/batleforc/weebo-forgejo/commit/180451574a0c5b5c75486390b6a991f8e5ed7b61)) - Max Batleforc, Claude Opus 5.5 (1M context)
#### Documentation
- (**perf**) resource budget measured on 2026-10-11 (#1) - ([0358491](https://github.com/batleforc/weebo-forgejo/commit/03584915e5c0f7f92b1695bcb2b3c9e515e3ce27)) - github-actions[bot], github-actions[bot]
#### Tests
- (**perf**) coverage reports the resource budget instead of enforcing it - ([e2644e1](https://github.com/batleforc/weebo-forgejo/commit/e2644e1cc657de710542d886afdbec6d85da5981)) - Max Batleforc, Claude Opus 5.5
- (**perf**) resource budget of the operator (kit v0.5.0) - ([39572cc](https://github.com/batleforc/weebo-forgejo/commit/39572cc929f012d4d00962f9715e8b7343f438b2)) - Max Batleforc, Claude Opus 5.5
- end-to-end coverage of every feature, 85% line gate in CI - ([da45034](https://github.com/batleforc/weebo-forgejo/commit/da450349e8115c26cd7ca6a134e379074b964276)) - Max Batleforc, Claude Opus 5.5 (1M context)
#### Build system
- depend on weebo-operator-kit v0.1.0 from git - ([81e63ad](https://github.com/batleforc/weebo-forgejo/commit/81e63ad9777e1162eee564cd08766ac8621b403d)) - Max Batleforc, Claude Opus 5.5
- provide vault through mise.toml for the real-Vault live test - ([2a68d0f](https://github.com/batleforc/weebo-forgejo/commit/2a68d0f117c7ba5d0e8af7b884792c37bffaa6a0)) - Max Batleforc, Claude Opus 5.5 (1M context)
#### Continuous Integration
- (**perf**) measure the resource budget every week (kit v0.8.0) - ([3c54fbf](https://github.com/batleforc/weebo-forgejo/commit/3c54fbf4dcb0768a95fb811a2f890368fdac1a5f)) - Max Batleforc, Claude Opus 5.5
#### Refactoring
- build on the kit's application skeleton (kit v0.6.0) - ([07ecb1b](https://github.com/batleforc/weebo-forgejo/commit/07ecb1bfa0cdc8f97b0ea48b469f3010a74f1da4)) - Max Batleforc, Claude Opus 5.5
- hexagonal clean-up and move shared plumbing to weebo-operator-kit - ([ada7678](https://github.com/batleforc/weebo-forgejo/commit/ada76780ec10dc00f550570ed58fe8815955c881)) - Max Batleforc, Claude Opus 5.5
#### Miscellaneous Chores
- stop tracking todo.md - ([3b0d0d7](https://github.com/batleforc/weebo-forgejo/commit/3b0d0d745eb1f0d56f48734ee0c4f125b30f35d5)) - Max Batleforc, Claude Opus 5.5

- - -

Changelog generated by [cocogitto](https://github.com/cocogitto/cocogitto).