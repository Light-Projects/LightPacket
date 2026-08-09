# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from typing import Optional, Union, Any
import copy


class BaseLayer:

    def __init__(self):
        self.payload: Optional['BaseLayer'] = None
        self._raw_payload: Optional[bytes] = None

    def __truediv__(self, other: Union['BaseLayer', bytes]) -> 'BaseLayer':
        new_layer = self.copy()

        new_layer.set_payload(other)
        return new_layer

    def __rtruediv__(self, other: Union['BaseLayer', bytes]) -> 'BaseLayer':
        if isinstance(other, BaseLayer):
            other.set_payload(self)
            return other
        elif isinstance(other, bytes):
            from .Raw import RawLayer
            raw = RawLayer(other)
            raw.set_payload(self)
            return raw
        else:
            raise TypeError(f"Cannot divide {type(other)} and {type(self)}")

    def set_payload(self, payload: Union['BaseLayer', bytes]) -> None:
        if isinstance(payload, BaseLayer):
            if self.payload is not None:
                last = self.payload
                while last.payload is not None:
                    last = last.payload
                last.set_payload(payload)
            else:
                self.payload = payload
        elif isinstance(payload, bytes):
            self.payload = None
            self._raw_payload = payload
        else:
            raise TypeError(f"Payload must be BaseLayer or bytes, got {type(payload)}")

    def get_payload_bytes(self) -> bytes:
        if self.payload is not None:
            return self.payload.build()
        elif self._raw_payload is not None:
            return self._raw_payload
        else:
            return b''

    def __getitem__(self, layer_type):
        if isinstance(self, layer_type):
            return self
        if self.payload is not None:
            return self.payload.__getitem__(layer_type)
        raise KeyError(f"Layer {layer_type.__name__} not found")

    def __contains__(self, layer_type):
        if isinstance(self, layer_type):
            return True
        if self.payload is not None:
            return layer_type in self.payload
        return False

    def build(self) -> bytes:
        raise NotImplementedError("Subclasses must implement build()")

    def copy(self) -> 'BaseLayer':
        return copy.copy(self)

    def __bytes__(self) -> bytes:
        return self.build()

    def __len__(self) -> int:
        return len(self.build())

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"

    def show(self, indent: int = 0) -> None:
        from .Decoration.Colors import BOLD, BLUE, PURPLE, RESET, CYAN

        pad = " " * indent
        print(f"{pad}{BOLD}--- [ {PURPLE}{self.__class__.__name__}{PURPLE}{RESET}{BOLD} ] ---{RESET}")
        args = self._show_fields()
        for arg in args:
            if arg is not None:
                print(f"{pad}   {arg}")

        if self.payload:
            print(f"{pad}  {BLUE}\\{RESET}")
            self.payload.show(indent + 4)

    def _show_fields(self) -> str:
        return str(self)
