"""Mongo `$let` expression for alert display source (SIEM name or agent hostname). Shared by dashboard and settings."""

from __future__ import annotations

from typing import Any

# Same logic as dashboard: real siem_source when not unknown; else src_endpoint / asset_meta hostname.
DISPLAY_SOURCE_MONGO_EXPR: dict[str, Any] = {
    '$let': {
        'vars': {
            'ss_raw': {'$trim': {'input': {'$ifNull': ['$siem_source', '']}}},
            'ss': {'$toLower': {'$trim': {'input': {'$ifNull': ['$siem_source', '']}}}},
            'host': {
                '$ifNull': [
                    '$src_endpoint.hostname',
                    {'$ifNull': ['$asset_meta.hostname', None]},
                ]
            },
        },
        'in': {
            '$cond': {
                'if': {
                    '$and': [
                        {'$ne': ['$$ss_raw', '']},
                        {'$not': {'$in': ['$$ss', ['unknown', '']]}},
                    ]
                },
                'then': '$$ss_raw',
                'else': {
                    '$cond': {
                        'if': {
                            '$and': [
                                {'$ne': ['$$host', None]},
                                {
                                    '$ne': [
                                        {
                                            '$trim': {
                                                'input': {
                                                    '$ifNull': [{'$toString': '$$host'}, ''],
                                                }
                                            }
                                        },
                                        '',
                                    ]
                                },
                            ]
                        },
                        'then': {'$trim': {'input': {'$ifNull': [{'$toString': '$$host'}, '']}}},
                        'else': 'Unknown',
                    }
                },
            }
        },
    }
}

# Parallel to DISPLAY_SOURCE_MONGO_EXPR: how the display label was derived.
SOURCE_KIND_MONGO_EXPR: dict[str, Any] = {
    '$let': {
        'vars': {
            'ss_raw': {'$trim': {'input': {'$ifNull': ['$siem_source', '']}}},
            'ss': {'$toLower': {'$trim': {'input': {'$ifNull': ['$siem_source', '']}}}},
            'host': {
                '$ifNull': [
                    '$src_endpoint.hostname',
                    {'$ifNull': ['$asset_meta.hostname', None]},
                ]
            },
        },
        'in': {
            '$cond': {
                'if': {
                    '$and': [
                        {'$ne': ['$$ss_raw', '']},
                        {'$not': {'$in': ['$$ss', ['unknown', '']]}},
                    ]
                },
                'then': 'siem',
                'else': {
                    '$cond': {
                        'if': {
                            '$and': [
                                {'$ne': ['$$host', None]},
                                {
                                    '$ne': [
                                        {
                                            '$trim': {
                                                'input': {
                                                    '$ifNull': [{'$toString': '$$host'}, ''],
                                                }
                                            }
                                        },
                                        '',
                                    ]
                                },
                            ]
                        },
                        'then': 'agent',
                        'else': 'unknown',
                    }
                },
            }
        },
    }
}
