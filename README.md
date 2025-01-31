<div align="center">

<img alt="Codecov" src="https://img.shields.io/codecov/c/github/maldwg/BICEP-utils?style=for-the-badge">
<img alt="GitHub branch status" src="https://img.shields.io/github/checks-status/maldwg/BICEP-utils/main?style=for-the-badge&label=Tests">


</div>

<br>

<div align="center">



# BICEP-utils
Repository for shared utils among the backend core and the IDS components.
It is injected via git submodules into the respective repository. 
The IDS components are depending on the implementation of the interfaces provided here, whereas the core needs to know the classes for its services. 

The following solutions are either planned or already implemented


| IDS Solution | Docker Image | Link | Status |
|-------------|-------------|------|--------|
| Slips       | `maxldwg/bicep-slips` | [Slips implementation](https://github.com/maldwg/BICEP-slips-image) | ✅ Available |
| Suricata    | `maxldwg/bicep-suricata` | [Suricata implementation](https://github.com/maldwg/BICEP-suricata-image) | ✅ Available |
| Snort       | `-` | `-` |  🕒 Planned  |
