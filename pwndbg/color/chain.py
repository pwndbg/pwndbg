#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pwndbg.color.theme as theme
import pwndbg.config as config
from pwndbg.color import generateColorFunction

config_arrow_color      = theme.ColoredParameter('chain-arrow-color', 'normal', 'color of chain formatting (arrow)')
config_contiguous_color = theme.ColoredParameter('chain-contiguous-marker-color', 'normal', 'color of chain formatting (contiguous marker)')

def arrow(x):
    return generateColorFunction(config.chain_arrow_color)(x)

def contiguous(x):
    return generateColorFunction(config.chain_contiguous_marker_color)(x)
