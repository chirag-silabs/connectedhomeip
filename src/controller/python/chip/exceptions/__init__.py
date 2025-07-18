#
#    Copyright (c) 2021 Project CHIP Authors
#    All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#

from __future__ import annotations

__all__ = [
    "ChipStackException",
    "ChipStackError",
    "DeviceError",
    "InvalidArgumentCount",
    "InvalidArgumentType",
    "UnknownAttribute",
    "UnknownCluster",
    "UnknownCommand",
]

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..native import PyChipError


class ChipStackException(Exception):
    def __reduce__(self):
        """
        Allows this exception to be pickled by returning a simplified Exception
        with the same message, ensuring it can be safely transferred across
        processes in multiprocessing environments.

        Note:
        This replaces the custom exception with a plain Exception during
        pickling, preserving the message but not the exception type, to avoid
        import errors in environments where this exception class is unavailable.
        """

        e = Exception(f"{str(self)}")
        return e.__reduce__()


class ChipStackError(ChipStackException):
    def __init__(self, code: int, msg=None):
        self.code = code
        self.msg = msg if msg else "Chip Stack Error %d" % self.code

    @classmethod
    def from_chip_error(cls, chip_error: PyChipError) -> ChipStackError:
        return cls(chip_error.code, str(chip_error))

    @property
    def err(self) -> int:
        return self.code

    def __str__(self):
        return self.msg


class DeviceError(ChipStackException):
    def __init__(self, profileId, statusCode, systemErrorCode, msg=None):
        self.profileId = profileId
        self.statusCode = statusCode
        self.systemErrorCode = systemErrorCode
        if not msg:
            self.msg = "[ %08X:%d ]" % (profileId, statusCode)
            if systemErrorCode:
                self.msg += " (system err %d)" % systemErrorCode
        else:
            self.msg = msg

    def __str__(self):
        return "Device Error: " + self.msg


class ClusterError(ChipStackException):
    pass


class InvalidArgumentCount(ChipStackException):
    def __init__(self, expect: int, given: int):
        self.expect = expect
        self.given = given

    def __str__(self):
        return "InvalidArgumentCount: Expect {}, {} given".format(self.expect, self.given)


class InvalidArgumentType(ChipStackException):
    def __init__(self, expect: type, given: type, name: str):
        self.expect = expect
        self.given = given
        self.argname = name

    def __str__(self):
        return "InvalidArgumentType: Argument {} should be {}, {} got".format(self.argname, self.expect, self.given)


class UnknownCluster(ClusterError):
    def __init__(self, cluster: str):
        self.cluster = cluster

    def __str__(self):
        return "UnknownCluster: {}".format(self.cluster)


class UnknownCommand(ClusterError):
    def __init__(self, cluster: str, command: str):
        self.cluster = cluster
        self.command = command

    def __str__(self):
        return "UnknownCommand: cluster: {}, command: {}".format(self.cluster, self.command)


class UnknownAttribute(ClusterError):
    def __init__(self, cluster: str, attribute: str):
        self.cluster = cluster
        self.attribute = attribute

    def __str__(self):
        return "UnknownAttribute: cluster: {}, attribute: {}".format(self.cluster, self.attribute)


class UnknownEvent(ClusterError):
    def __init__(self, cluster: str, event: str):
        self.cluster = cluster
        self.event = event

    def __str__(self):
        return "UnknownEvent: cluster: {}, event: {}".format(self.cluster, self.event)
