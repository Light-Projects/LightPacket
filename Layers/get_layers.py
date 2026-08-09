# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


def get_all_layers(layer):
    layers = {}
    current = layer
    while current:
        layers[current.__class__.__name__] = current
        current = current.payload

    return layers

def printpc(layers):
    for layer in layers:
        print(layer.__class__.__name__)