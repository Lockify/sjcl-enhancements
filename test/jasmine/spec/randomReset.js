describe(
    "randomReset",
    function() {
        it(
            "should re-initialize Random to unseeded state",
            function () {
                sjclE.random.RandomInit();
                expect(
                    function () {
                        Random.random_words(2);
                    }
                ).toThrow(
                    sjcl.exception.notReady("generator isn't seeded")
                );
            }
        );
    }
);