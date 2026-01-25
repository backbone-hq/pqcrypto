"""
A custom build hook for Hatchling to modify the build tag.
This is important for packages built for specific platforms, architectures and python versions.

For clarity:
This hook results in wheels like `pqcrypto-<version>-cp313-cp313-manylinux_2_35_x86_64` instead of the generic `pqcrypto-<version>-py3-none-any`
"""

from hatchling.builders.hooks.plugin.interface import BuildHookInterface
from packaging.tags import sys_tags


class BuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        tag = next(sys_tags())
        build_data["tag"] = "-".join([tag.interpreter, tag.abi, tag.platform])
        return build_data
