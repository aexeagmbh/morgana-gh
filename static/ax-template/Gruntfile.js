/* jshint node: true */
/*jslint node: true */
module.exports = function (grunt) {
    'use strict';

    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),

        sass: {
            options: {
                loadPath: [
                    __dirname + '/scss',
                    __dirname + '/bower_components/foundation/scss',
                    __dirname + '/bower_components'
                ],
                sourcemap: 'auto',
                bundleExec: true
            },
            dist: {
                files: {
                    'css/ax-template.css': 'scss/app.scss'
                }
            }
        },

        watch: {
            grunt: {
                files: ['Gruntfile.js']
            },

            sass: {
                files: 'scss/**/*.scss',
                tasks: ['sass']
            },

            js: {
                files: [
                    'js/*/*.js'
                ],
                tasks: ['buildJs']
            }
        },

        jslint: {
            'gruntfile': {
                src: [
                    'Gruntfile.js'
                ]
            },
            'ax-template': {
                src: [
                    'js/ax-template/*.js'
                ]
            }
        },

        concat: {
            "ax-template": {
                dest: 'js/ax-template.js',
                src: [
                    'js/ax-template/*.js'
                ]
            },
            "foundation": {
                dest: 'js/foundation.js',
                src: ['bower_components/foundation/js/foundation/foundation.js', 'bower_components/foundation/js/foundation/*.js']
            }
        },

        uglify: {
            build: {
                src: 'js/ax-template.js',
                dest: 'js/ax-template.min.js'
            },
            foundation: {
                src: 'js/foundation.js',
                dest: 'js/foundation.min.js'
            }
        }
    });

   // grunt.loadNpmTasks('grunt-sass');
    grunt.loadNpmTasks('grunt-contrib-sass');
    grunt.loadNpmTasks('grunt-contrib-watch');
    grunt.loadNpmTasks('grunt-contrib-copy');
    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-contrib-concat');
    grunt.loadNpmTasks('grunt-jslint');

    grunt.registerTask('buildJs', ['concat', 'uglify']);
    grunt.registerTask('build', ['sass', 'buildJs']);
    grunt.registerTask('default', ['build', 'watch']);
};
