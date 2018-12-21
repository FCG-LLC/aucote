"""
Node scan end
"""

from yoyo import step

__depends__ = {'20181219_01_OnYTP-init-tables'}

steps = [
    step('ALTER TABLE nodes_scans add column end_timestamp int null;')
]
