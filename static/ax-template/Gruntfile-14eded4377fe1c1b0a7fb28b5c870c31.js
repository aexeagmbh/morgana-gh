module.exports=function(s){"use strict";s.initConfig({pkg:s.file.readJSON("package.json"),sass:{options:{loadPath:[__dirname+"/scss",__dirname+"/bower_components/foundation/scss",__dirname+"/bower_components"],sourcemap:"auto",bundleExec:!0},dist:{files:{"css/ax-template-5adbb0085a3d5c8908d2fc65c448ab52.css":"scss/app.scss"}}},watch:{grunt:{files:["Gruntfile-14eded4377fe1c1b0a7fb28b5c870c31.js"]},sass:{files:"scss/**/*.scss",tasks:["sass"]},js:{files:["js/*/*.js"],tasks:["buildJs"]}},jslint:{gruntfile:{src:["Gruntfile-14eded4377fe1c1b0a7fb28b5c870c31.js"]},"ax-template":{src:["js/ax-template/*.js"]}},concat:{"ax-template":{dest:"js/ax-template-45dbd0284f9a91c060c109165be4d37e.js",src:["js/ax-template/*.js"]},foundation:{dest:"js/foundation-d1aff756e520e41abefa215e8913b79b.js",src:["bower_components/foundation/js/foundation/foundation.js","bower_components/foundation/js/foundation/*.js"]}},uglify:{build:{src:"js/ax-template-45dbd0284f9a91c060c109165be4d37e.js",dest:"js/ax-template.min-45dbd0284f9a91c060c109165be4d37e.js"},foundation:{src:"js/foundation-d1aff756e520e41abefa215e8913b79b.js",dest:"js/foundation.min-837a2115d31f2b3ff801e48d070ceac1.js"}}}),s.loadNpmTasks("grunt-contrib-sass"),s.loadNpmTasks("grunt-contrib-watch"),s.loadNpmTasks("grunt-contrib-copy"),s.loadNpmTasks("grunt-contrib-uglify"),s.loadNpmTasks("grunt-contrib-concat"),s.loadNpmTasks("grunt-jslint"),s.registerTask("buildJs",["concat","uglify"]),s.registerTask("build",["sass","buildJs"]),s.registerTask("default",["build","watch"])};