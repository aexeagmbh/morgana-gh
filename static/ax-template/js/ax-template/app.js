/*jslint browser: true, unparam: true */
/*global jQuery*/

window.AX = window.AX || {};
window.AX.foundation = window.AX.foundation || {};
window.AX.foundation.settingCallBacks = window.AX.foundation.settingCallBacks || {};
window.AX.ravenJs = window.AX.ravenJs || {};
window.AX.ravenJs.config = window.AX.ravenJs.config || {sentryUrl: '', ravenOptions: {}};

(function ($) {
    'use strict';

    var foundationMagellanDefaultSettingsCallBack,
        initFoundation,
        initDataClickAs,
        initRavenJs;

    foundationMagellanDefaultSettingsCallBack = function () {
        var navigationRowOuterHeight =  $('.navigationRow .contain-to-grid').outerHeight();
        return {
            'threshold': (-1) * navigationRowOuterHeight,
            'destination_threshold': navigationRowOuterHeight,
            'fixed_top': navigationRowOuterHeight
        };
    };
    window.AX.foundation.settingCallBacks['magellan-expedition'] = window.AX.foundation.settingCallBacks['magellan-expedition'] || foundationMagellanDefaultSettingsCallBack;


    initFoundation = function () {
        var foundationOptions = {};
        $.each(window.AX.foundation.settingCallBacks, function (key, callBack) {
            foundationOptions[key] = callBack();
        });

        $(document).foundation(foundationOptions).trigger('scroll');
    };

    initDataClickAs = function () {
        $(document).on('click', '[data-clickas]', function (e) {
            var $this = $(this);

            e.preventDefault();
            $('a[href="' + $this.data('clickas') + '"]').trigger('click');
        });
    };

    initRavenJs = function () {
        var ravenJsConfig = window.AX.ravenJs.config,
            ravenOptions = ravenJsConfig.ravenOptions || {},
            sentryUrl = ravenJsConfig.sentryUrl || '';

        if (window.Raven && sentryUrl) {
            window.Raven.config(sentryUrl, ravenOptions).install();
        }
    };

    jQuery(function($) {

        initRavenJs();
        initFoundation();
        initDataClickAs();

    });


}(jQuery));
