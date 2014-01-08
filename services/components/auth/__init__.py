# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""Authentication and authorization component."""

import os
import sys

# For oauth2client.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(BASE_DIR, 'third_party'))

__all__ = []

from api import *
__all__.extend(api.__all__)

from tokens import *
__all__.extend(tokens.__all__)

from handler import *
__all__.extend(handler.__all__)

from model import *
__all__.extend(model.__all__)

from oauth import *
__all__.extend(oauth.__all__)
