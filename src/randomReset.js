/**
 * randomReset.js
 * Un-seed the SJCL Fortuna random number generator, in
 * random.js.  As shipped, SJCL lacks this ability. The actual
 * random.js source is untouched. Because of problems making a deep
 * copy of SJCL's initial state variables, it maintains a
 * cut-and-paste copy, which RandomInit() can reinstate on demand.
 * This file must be loaded after sjcl/random.js.
 */
sjclE.random = {
    RandomInit: function () {
        var _sjcl_random_default = {
            _pools                   : [new sjcl.hash.sha256()],
            _poolEntropy             : [0],
            _reseedCount             : 0,
            _robins                  : {},
            _eventId                 : 0,

            _collectorIds            : {},
            _collectorIdNext         : 0,

            _strength                : 0,
            _poolStrength            : 0,
            _nextReseed              : 0,
            _key                     : [0, 0, 0, 0, 0, 0, 0, 0],
            _counter                 : [0, 0, 0, 0],
            _cipher                  : undefined,
            _defaultParanoia         : 6,

            /* event listener stuff */
            _collectorsStarted       : false,
            _callbacks               : {progress: {}, seeded: {}},
            _callbackI               : 0
        };
        for (var key in _sjcl_random_default) {
            if (_sjcl_random_default.hasOwnProperty(key)) {
                sjcl.random[key] = _sjcl_random_default[key];
            }
        }

        sjcl.random['motion_x'] = 0;
        sjcl.random['motion_y'] = 0;
        sjcl.random['motion_z'] = 0;

    }
};

// Adapter for old method names
var Random = sjcl.random;

Random._motion_collector = function (ev) {
    var acc = ev.accelerationIncludingGravity;
    var x = acc.x, y = acc.y, z = acc.z;

    var delta_x = Math.abs(sjcl.random['motion_x'] - x);
    var delta_y = Math.abs(sjcl.random['motion_y'] - y);
    var delta_z = Math.abs(sjcl.random['motion_z'] - z);
    if (delta_x > 1 || delta_y > 1 || delta_z > 1) {
        sjcl.random.addEntropy([x, y, z], 1, "motion");
        sjcl.random['motion_x'] = x;
        sjcl.random['motion_y'] = y;
        sjcl.random['motion_z'] = z;
    }
};

Random.add_entropy = Random.addEntropy;
Random.get_progress = Random.getProgress;
Random.is_ready = Random.isReady;
Random._mouse_collector = Random._mouseCollector;
Random.random_words = Random.randomWords;
