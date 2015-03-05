/* jshint ignore:start */

/* jshint ignore:end */

define('morgana/adapters/application', ['exports', 'ember-data', 'ember', 'morgana/mixins/server-side-model-adapter', 'morgana/config/environment'], function (exports, DS, Ember, ServerSideModelAdapterMixin, config) {

    'use strict';

    exports['default'] = DS['default'].RESTAdapter.extend(ServerSideModelAdapterMixin['default'], {
        namespace: config['default'].restAdapter.namespace,
        host: config['default'].restAdapter.host,

        pathForType: function (type) {
            return Ember['default'].String.underscore(type).replace(/_/g, '-');
        },
        buildURL: function (type, id) {
            var url = this._super(type, id);

            if (url.charAt(url.length - 1) !== '/') {
                url += '/';
            }

            return url;
        }
    });

});
define('morgana/adapters/ax-company', ['exports', 'morgana/adapters/application'], function (exports, ApplicationAdapter) {

    'use strict';

    exports['default'] = ApplicationAdapter['default'].extend({
        pathForType: function () {
            return 'me/company';
        },
        useUpdateFieldsForDynamicModels: true
    });

});
define('morgana/adapters/bulk-upload-general', ['exports', 'morgana/adapters/django-rest-file'], function (exports, DjangoRestFileAdapter) {

    'use strict';

    exports['default'] = DjangoRestFileAdapter['default'].extend({
        pathForType: function () {
            return 'bulkupload';
        }
    });

});
define('morgana/adapters/bulk-upload', ['exports', 'morgana/adapters/bulk-upload-general'], function (exports, BulkUploadGeneralAdapter) {

	'use strict';

	exports['default'] = BulkUploadGeneralAdapter['default'].extend({
	});

});
define('morgana/adapters/content-project-export', ['exports', 'morgana/adapters/application'], function (exports, ApplicationAdapter) {

    'use strict';

    exports['default'] = ApplicationAdapter['default'].extend({
        pathForType: function () {
            return '';
        }
    });

});
define('morgana/adapters/content-request', ['exports', 'morgana/adapters/application'], function (exports, ApplicationAdapter) {

    'use strict';

    exports['default'] = ApplicationAdapter['default'].extend({
        pathForType: function () {
            return ''; //Overwrite in route!
        },
        find: function (store, type) {
            return this.ajax(this.buildURL(type.typeKey), 'GET');
        }
    });

});
define('morgana/adapters/django-rest-file', ['exports', 'ember', 'morgana/adapters/application'], function (exports, Ember, ApplicationAdapter) {

    'use strict';

    exports['default'] = ApplicationAdapter['default'].extend({
        createRecord: function (store, type, record) {
            var url = this.buildURL(type.typeKey),
                serializedData = store.serializerFor(type.typeKey).serialize(record),
                formData = new FormData(),
                key;
            for (key in serializedData) {
                formData.append(key, serializedData[key]);
            }

            return this.ajax(url, "POST", {
                data: formData,
                contentType: false,
                processData: false
            });
        },
        ajax: function (url, type, options) {
            var adapter = this;

            return new Ember['default'].RSVP.Promise(function (resolve, reject) {
                var hash = options;

                hash.url = url;
                hash.type = type;
                hash.success = function (json) {
                    Ember['default'].run(null, resolve, json);
                };
                hash.error = function (jqXHR) {
                    Ember['default'].run(null, reject, adapter.ajaxError(jqXHR));
                };
                Ember['default'].$.ajax(hash);
            }, "DS: RESTAdapter#ajax " + type + " to " + url);
        }
    });

});
define('morgana/adapters/image-request', ['exports', 'morgana/adapters/content-request'], function (exports, ContentRequestAdapter) {

	'use strict';

	exports['default'] = ContentRequestAdapter['default'].extend({
	});

});
define('morgana/adapters/text-request', ['exports', 'morgana/adapters/content-request'], function (exports, ContentRequestAdapter) {

	'use strict';

	exports['default'] = ContentRequestAdapter['default'].extend({
	});

});
define('morgana/adapters/thing', ['exports', 'morgana/adapters/application'], function (exports, ApplicationAdapter) {

    'use strict';

    exports['default'] = ApplicationAdapter['default'].extend({
        pathForType: function () {
            return ''; //Overwrite in route!
        }
    });

});
define('morgana/adapters/user-check-list', ['exports', 'morgana/adapters/application'], function (exports, ApplicationAdapter) {

    'use strict';

    exports['default'] = ApplicationAdapter['default'].extend({
        pathForType: function () {
            return 'me/check_list/';
        }
    });

});
define('morgana/adapters/user', ['exports', 'morgana/adapters/application'], function (exports, ApplicationAdapter) {

    'use strict';

    exports['default'] = ApplicationAdapter['default'].extend({
        pathForType: function () {
            return 'me';
        }
    });

});
define('morgana/app', ['exports', 'ember', 'ember/resolver', 'ember/load-initializers', 'morgana/config/environment', 'morgana/mixins/flash-messages-route', 'morgana/mixins/loading-stages-route', 'morgana/mixins/loading-stages-controller'], function (exports, Ember, Resolver, loadInitializers, config, FlashMessagesRouteMixin, LoadingStagesRouteMixin, LoadingStagesControllerMixin) {

  'use strict';

  var getCookie = function (name) {
      var cookieValue = null;
      if (document.cookie && document.cookie !== '') {
          var cookies = document.cookie.split(';');
          for (var i = 0; i < cookies.length; i++) {
              var cookie = Ember['default'].$.trim(cookies[i]);
              // Does this cookie string begin with the name we want?
              if (cookie.substring(0, name.length + 1) === (name + '=')) {
                  cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                  break;
              }
          }
      }
      return cookieValue;
  },
  csrfSafeMethod = function (method) {
      // these HTTP methods do not require CSRF protection
      return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
  },
  csrftoken = getCookie('csrftoken');

  Ember['default'].$.ajaxSetup({
      headers: { "ember": true },
      beforeSend: function (xhr, settings) {
          if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
              xhr.setRequestHeader("X-CSRFToken", getCookie('csrftoken'));
          }
      },
  //    xhrFields: {withCredentials: true },
  //    crossDomain: true
  });

  Ember['default'].MODEL_FACTORY_INJECTIONS = true;

  var App = Ember['default'].Application.extend({
    modulePrefix: config['default'].modulePrefix,
    podModulePrefix: config['default'].podModulePrefix,
    Resolver: Resolver['default'],
    rootElement: config['default'].rootElement
  });

  // FIXME use something like a default Route
  Ember['default'].Route.reopen(FlashMessagesRouteMixin['default'], LoadingStagesRouteMixin['default']);
  Ember['default'].ControllerMixin.reopen(LoadingStagesControllerMixin['default']);
  loadInitializers['default'](App, config['default'].modulePrefix);

  exports['default'] = App;

});
define('morgana/authenticators/myax', ['exports', 'ember', 'simple-auth/authenticators/base', 'morgana/config/environment', 'morgana/store'], function (exports, Ember, Base, ENV, store) {

    'use strict';

    exports['default'] = Base['default'].extend({

    //    init: function() {
    //        var globalConfig = ENV['simple-auth'] || {};
    //        this.serverTokenEndpoint =  globalConfig.serverTokenEndpoint;
    //        this._super();
    //    },
    //
    //    restore: function (data) {
    //        return new Ember.RSVP.Promise(function (resolve, reject) {
    //            if (!Ember.isEmpty(data.currentUserId)) {
    //                resolve(data);
    //            } else {
    //                reject();
    //            }
    //        });
    //    },
    //
    //    authenticate: function (options) {
    //        var _this = this;
    //        return new Ember.RSVP.Promise(function (resolve, reject) {
    //            var data = { email: options.identification, password: options.password };
    //            _this.makeRequest(_this.serverTokenEndpoint, data, "POST").then(function (response) {
    //                Ember.run(function () {
    //                    resolve({currentUserId: response.user});
    //                });
    //            }, function (xhr, status, error) {
    //                Ember.run(function () {
    //                    reject();
    //                });
    //            });
    //        });
    //    },
    //
    //    invalidate: function () {
    //        var _this = this;
    //        return new Ember.RSVP.Promise(function (resolve) {
    //            _this.makeRequest(_this.serverTokenEndpoint, {}, "DELETE").then(function () {
    //                resolve();
    //            });
    //        });
    //    },
    //
    //    makeRequest: function (url, data, type) {
    //        return Ember.$.ajax({
    //            url: url,
    //            type: type,
    //            data: data,
    //            dataType: 'json'
    //        });
    //    }

        init: function () {
            var globalConfig = ENV['default']['simple-auth'] || {};
            this.serverTokenEndpoint = globalConfig.serverTokenEndpoint;
            this._super();
        },

        authenticate: function (credentials) {
            var _this = this;
            return new Ember['default'].RSVP.Promise(function (resolve, reject) {
                var data = { email: credentials.identification, password: credentials.password };
                _this.makeRequest(_this.serverTokenEndpoint, data, "POST").then(function (response) {
                    Ember['default'].run(function () {
                        var data = {
                            currentUserId: response.user,
                            token: response.token
                        };
                        resolve(data);
                    });
                }, function (xhr, status, error) {
                    Ember['default'].run(function () {
                        reject();
                    });
                });
            });
        },

        restore: function (data) {
            return new Ember['default'].RSVP.Promise(function (resolve, reject) {
                if (!Ember['default'].isEmpty(data.token)) {
                    resolve(data);
                } else {
                    reject();
                }
            });
        },

        invalidate: function () {
            var _this = this;
            return new Ember['default'].RSVP.Promise(function (resolve) {
                _this.makeRequest(_this.serverTokenEndpoint, {}, "DELETE").then(function () {
                    resolve();
                });
            });
        },

        makeRequest: function (url, data, type) {
            return Ember['default'].$.ajax({
                url: url,
                type: type,
                data: data,
                dataType: 'json'
            });
        }

    });

});
define('morgana/authorizers/myax', ['exports', 'ember', 'simple-auth/authorizers/base'], function (exports, Ember, Base) {

    'use strict';

    exports['default'] = Base['default'].extend({
        authorize: function (jqXHR, requestOptions) {
            var accessToken = this.get('session.token');
            if (this.get('session.isAuthenticated') && !Ember['default'].isEmpty(accessToken)) {
                jqXHR.setRequestHeader('Authorization', 'Token ' + accessToken);
            }
        }
    });

});
define('morgana/components/button-with-loader', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Component.extend({
        isLoading: false,
        isAlert: false,
        displayAsButton: true,
        buttonText: '',

        actions: {

            showLoading: function() {
                this.set('isLoading', true);
                this.sendAction('action');
            }
        }
    });

});
define('morgana/controllers/application', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend({
        currentUser: Ember['default'].computed.alias('session.currentUser')
    });

});
define('morgana/controllers/content-project/bulk-upload/upload', ['exports', 'ember', 'morgana/mixins/flash-message', 'morgana/mixins/server-side-field-error'], function (exports, Ember, FlashMessageMixin, ServerSideFieldErrorMixin) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(FlashMessageMixin['default'], ServerSideFieldErrorMixin['default'], {
        actions: {
            upload: function () {
                var controller = this,
                    bulkupload = this.get('model');
                bulkupload.save().then(function (bulkupload) {
                    controller.addSuccessMessage('File successfully uploaded. It will take a second for the new data to be shown.');
                    controller.hideLoading('upload');
                    controller.transitionToRoute('content-project.index', bulkupload.get('contentProject'));
                }, function (e) {
                    controller.hideLoading('upload');
                    controller.handleServerSideError('Error uploading file!', e);
                });
            },
            back: function () {
                var bulkupload = this.get('model'),
                    contentProject = bulkupload.get('contentProject');
                bulkupload.deleteRecord();
                this.hideLoading('back');
                this.transitionToRoute('content-project.index', contentProject);
            }
        }
    });

});
define('morgana/controllers/content-project/content-project-exports/index', ['exports', 'ember', 'morgana/mixins/pagination'], function (exports, Ember, pagination) {

    'use strict';

    exports['default'] = Ember['default'].ArrayController.extend(pagination.PaginationMixin, {
        model: Ember['default'].A(),
        itemObjectName: 'contentProjectExport',
        itemsPerPage: 10,

        meta: Ember['default'].computed('model', function () {
            return this.store.metadataFor("contentProjectExport");
        }),

        actions: {
            'downloadFile': function (contentProjectExport) {
                var store = this.get('store'),
                    url = contentProjectExport.get('downloadUrl');

                if (url) {
                    window.location.href = url;
                    // FIXME: add some error handling
                }
            }
        }
    });

});
define('morgana/controllers/content-project/delete', ['exports', 'ember', 'morgana/mixins/flash-message', 'morgana/mixins/server-side-field-error'], function (exports, Ember, FlashMessageMixin, ServerSideFieldErrorMixin) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(FlashMessageMixin['default'], ServerSideFieldErrorMixin['default'], {
        actions: {
            "delete": function () {
                var controller = this,
                    contentProject = this.get('model');

                contentProject.destroyRecord().then(function () {
                    controller.addSuccessMessage('Content Project deleted.');
                    controller.hideLoading('delete');
                    controller.transitionToRoute('home');
                }, function (e) {
                    controller.hideLoading('delete');
                    controller.handleServerSideError('Error deleting Content Project!', e);
                });
            },
            back: function () {
                var contentProject = this.get('model');
                contentProject.rollback();
                this.hideLoading('back');
                this.transitionToRoute('content-project.index', contentProject);
            }
        }
    });

});
define('morgana/controllers/content-project/edit', ['exports', 'ember', 'morgana/mixins/flash-message', 'morgana/mixins/server-side-field-error'], function (exports, Ember, FlashMessageMixin, ServerSideFieldErrorMixin) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(FlashMessageMixin['default'], ServerSideFieldErrorMixin['default'], {
        actions: {
            edit: function () {
                var controller = this,
                    contentProject = this.get('model');

                contentProject.get('engineConfiguration').then(function (ec) {
                    contentProject.set('engineConfiguration', ec);
                    contentProject.save().then(function (contentProject) {
                        controller.addSuccessMessage('Content Project saved.');
                        controller.hideLoading('edit');
                        controller.transitionToRoute('content-project.index', contentProject);
                    }, function (e) {
                        controller.hideLoading('edit');
                        controller.handleServerSideError('Error editing Content Project!', e);
                    });
                });
            },
            back: function () {
                var contentProject = this.get('model');
                contentProject.rollback();
                this.hideLoading('back');
                this.transitionToRoute('content-project.index', contentProject);
            }
        }
    });

});
define('morgana/controllers/content-project/index', ['exports', 'ember', 'morgana/mixins/permissions', 'morgana/mixins/flash-message'], function (exports, Ember, permissions, FlashMessageMixin) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(FlashMessageMixin['default'], permissions.PermissionsMixin, {
        model: {},

        actions: {
            createThing: function () {
                this.hideLoading('addThing');
                this.transitionToRoute('content-project.thing-type.thing-new');
            },
            uploadFile: function () {
                this.hideLoading('addThing');
                this.transitionToRoute('content-project.bulk-upload.upload', this.get('model.id'));
            },
            generateContent: function () {
                var controller = this,
                    flashMessages = this.get('controllers.flash-messages'),
                    store = this.get('store'),
                    model = this.get('model'),
                    adapter = store.adapterFor('contentProject'),
                    url = adapter.buildURL('contentProject', model.get('id')),
                    promise = adapter.ajax(url + 'generate_content/', 'POST');
                promise.then(function (res) {
                    var responseContent = res.contentProject,
                        msg,
                        msgStatus;
                    if (responseContent.status === 'CALLED') {
                        msg = 'Content requests for Objects in "' + model.get('name') + '" have been successfully scheduled.';
                        msgStatus = 'success';
                    } else if (responseContent.status === 'NOT_CALLED') {
                        msgStatus = 'warning';
                        msg = Ember['default'].View.create({
                            controller: controller,
                            tagName: 'span',
                            template:  Ember['default'].Handlebars.compile('There is already content for all Objects. Maybe you want to <a {{action "forceGenerateContent"}}>force regeneration</a>?')
                        });
                    }
                    controller.hideLoading('generateContent');
                    flashMessages.addMessage(msg, msgStatus);
                    flashMessages.now();
                }, function (e) {
                    var msgStatus,
                        msg;

                    if (e && e.contentProject && e.contentProject.message) {
                        msgStatus = 'error';
                        msg = Ember['default'].View.create({
                            controller: controller,
                            tagName: 'span',
                            template:  Ember['default'].Handlebars.compile(e.contentProject.message)
                        });
                        flashMessages.addMessage(msg, msgStatus);
                        flashMessages.now();
                    } else {
                        Raven.captureMessage('Error generating Content for Content Project!', e);
                    }
                    controller.hideLoading('generateContent');
                });
            },
            forceGenerateContent: function () {
                var controller = this,
                    flashMessages = this.get('controllers.flash-messages'),
                    store = this.get('store'),
                    model = this.get('model'),
                    adapter = store.adapterFor('contentProject'),
                    url = adapter.buildURL('contentProject', model.get('id')),
                    promise = adapter.ajax(url + 'generate_content/?force=true', 'POST');

                promise.then(function (res) {
                    var responseContent = res.contentProject,
                        msg,
                        msgStatus;
                    if (responseContent.status === 'CALLED') {
                        msg = 'Content requests for Objects in "' + model.get('name') + '" have been successfully scheduled.';
                        msgStatus = 'success';
                    } else if (responseContent.status === 'NOT_CALLED') {
                        msgStatus = 'error';
                        msg = 'Sorry, an error occured. This should not have happened';
                        Raven.captureMessage('Error generating Content for Content Project! Force returned NOT_CALLED', res);
                    }
                    controller.hideLoading('generateContent');
                    flashMessages.addMessage(msg, msgStatus);
                    flashMessages.now();
                }, function (e) {
                    var msgStatus,
                        msg;
                    if (e && e.contentProject && e.contentProject.message) {
                        msgStatus = 'error';
                        msg = Ember['default'].View.create({
                            controller: controller,
                            tagName: 'span',
                            template:  Ember['default'].Handlebars.compile(e.contentProject.message)
                        });
                        flashMessages.addMessage(msg, msgStatus);
                        flashMessages.now();
                    } else {
                        Raven.captureMessage('Error generating Content for Content Project!', e);
                    }
                    controller.hideLoading('generateContent');
                });
            },
            downloadContent: function () {
                var url = '/dashboard/content_project/' + this.get('model').get('id') +  '/export_xlsx/?generated_texts=1';
                this.hideLoading('downloadContent');
                window.location.href = url;
            },
            downloadExample: function () {
                var url = '/dashboard/content_project/' + this.get('model').get('id') +  '/export_xlsx/?example=1';
                this.hideLoading('downloadContent');
                window.location.href = url;
            },
            downloadImages: function () {
                var url = '/dashboard/content_project/' + this.get('model').get('id') + '/download_images_zip/';
                this.hideLoading('downloadImages');
                window.location.href = url;
            },
            createImageZip: function () {
                var url = '/dashboard/content_project/' + this.get('model').get('id') + '/generate_images_zip/';
                this.hideLoading('createImageZip');
                window.location.href = url;
            },
            buyCredits: function () {
                this.hideLoading('buyCredits');
                this.transitionToRoute('credits');
            },
            edit: function () {
                this.hideLoading('edit');
                this.transitionToRoute('content-project.edit', this.get('model'));
            },
            "delete": function () {
                this.hideLoading('edit');
                this.transitionToRoute('content-project.delete', this.get('model'));
            },
            back: function () {
                this.hideLoading('back');
                this.transitionToRoute('home');
            }

        }
    });

});
define('morgana/controllers/content-project/thing-type/thing-new', ['exports', 'ember', 'morgana/mixins/flash-message', 'morgana/mixins/permissions', 'morgana/mixins/server-side-model-fields', 'morgana/mixins/server-side-field-error'], function (exports, Ember, FlashMessageMixin, permissions, ServerSideModelFieldsMixin, ServerSideFieldErrorMixin) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(FlashMessageMixin['default'], ServerSideFieldErrorMixin['default'], permissions.PermissionsMixin, ServerSideModelFieldsMixin['default'], {
        engineConfiguration: null,

        actions: {
            create: function () {
                var controller = this,
                    thing = this.get('model');

                thing.get('contentProject').then(function (cp) {
                    thing.set('contentProject', cp);
                    thing.save().then(function (thing) {
                        controller.addSuccessMessage('Object created.');
                        controller.hideLoading('create');
                        controller.transitionToRoute('content-project.thing-type.thing.index', thing.get('id'));
                    }, function (e) {
                        controller.hideLoading('create');
                        controller.handleServerSideError('Error creating Object!', e);
                    });
                });
            },
            back: function () {
                var thing = this.get('model');
                thing.rollback();
                this.hideLoading('back');
                this.transitionToRoute('content-project.index');
            }
        }
    });

});
define('morgana/controllers/content-project/thing-type/thing/delete', ['exports', 'ember', 'morgana/mixins/flash-message', 'morgana/mixins/server-side-field-error'], function (exports, Ember, FlashMessageMixin, ServerSideFieldErrorMixin) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(FlashMessageMixin['default'], ServerSideFieldErrorMixin['default'], {

        actions: {
            "delete": function () {
                var controller = this,
                    thing = this.get('model'),
                    thingName = thing.get('name'),
                    contentProjectId = controller.get('contentProject').get('id');

                thing.destroyRecord().then(function () {

                    controller.addSuccessMessage(Ember['default'].String.fmt('Object %@ deleted.', thingName));
                    controller.hideLoading('delete');
                    controller.transitionToRoute('content-project.index', contentProjectId);
                }, function (e) {
                    controller.hideLoading('delete');
                    controller.handleServerSideError('Error deleting Object!', e);
                });
            },
            back: function () {
                var thing = this.get('model');
                thing.rollback();
                this.hideLoading('back');
                this.transitionToRoute('content-project.thing-type.thing.index', thing.get('id'));
            }
        }
    });

});
define('morgana/controllers/content-project/thing-type/thing/edit', ['exports', 'ember', 'morgana/mixins/flash-message', 'morgana/mixins/permissions', 'morgana/mixins/server-side-model-fields', 'morgana/mixins/server-side-field-error'], function (exports, Ember, FlashMessageMixin, permissions, ServerSideModelFieldsMixin, ServerSideFieldErrorMixin) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(FlashMessageMixin['default'], ServerSideFieldErrorMixin['default'], permissions.PermissionsMixin, ServerSideModelFieldsMixin['default'], {
        engineConfiguration: null,

        actions: {
            edit: function () {
                var controller = this,
                    thing = this.get('model');

                thing.get('contentProject').then(function (cp) {
                    thing.set('contentProject', cp);
                    thing.save().then(function (thing) {
                        controller.addSuccessMessage('Object saved.');
                        controller.hideLoading('edit');
                        controller.transitionToRoute('content-project.thing-type.thing.index', thing.get('id'));
                    }, function (e) {
                        controller.hideLoading('edit');
                        controller.handleServerSideError('Error editing Object!', e);
                    });
                });
            },
            back: function () {
                var thing = this.get('model');
                thing.rollback();
                this.hideLoading('back');
                this.transitionToRoute('content-project.thing-type.thing.index', thing.get('id'));
            }
        }
    });

});
define('morgana/controllers/content-project/thing-type/thing/index', ['exports', 'ember', 'morgana/mixins/flash-message', 'morgana/mixins/permissions', 'morgana/mixins/server-side-model-fields', 'morgana/mixins/jira-report'], function (exports, Ember, FlashMessageMixin, permissions, ServerSideModelFieldsMixin, JiraReportMixin) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(JiraReportMixin['default'], FlashMessageMixin['default'], permissions.PermissionsMixin, ServerSideModelFieldsMixin['default'], {
        engineConfiguration: Ember['default'].K(),

        infoPanelStatusCssClass: Ember['default'].computed('model.contentGenerationStatusCssClass', function () {
            return 'panel-' + this.get('model').get('contentGenerationStatusCssClass');
        }),

        contentRequest: null,

        actions: {
            buyCredits: function () {
                this.hideLoading('buyCredits');
                this.transitionToRoute('credits');
            },
            generateContent: function () {
                var controller = this,
                    flashMessages = this.get('controllers.flash-messages'),
                    store = this.get('store'),
                    model = this.get('model'),
                    thingTypeName = model.constructor.typeKey,
                    adapter = store.getDynamicAdapter(thingTypeName),
                    url = adapter.buildURL(model.constructor.typeKey, model.get('id')),
                    promise = adapter.ajax(url + 'generate_content/', 'POST');

                promise.then(function (res) {
                    var msg,
                        msgStatus;
                    if (res[thingTypeName].status === 'CALLED') {
                        msg = 'Content request for "' + model.get('name') + '" has been succesfully scheduled.';
                        msgStatus = 'success';
                    } else if (res[thingTypeName].status === 'NOT_CALLED') {
                        msgStatus = 'warning';
                        msg = Ember['default'].View.create({
                            controller: controller,
                            tagName: 'span',
                            template:  Ember['default'].Handlebars.compile('There is already content for "' + model.get('name') + '". Maybe you want to <a {{action "forceGenerateContent"}}>force regeneration</a>?')
                        });
                    }
                    flashMessages.addMessage(msg, msgStatus);
                    controller.hideLoading('generateContent');
                    flashMessages.now();
                }, function (e) {
                    controller.hideLoading('generateContent');
                    Raven.captureMessage('Error generating Content!', e);
                });

            },
            forceGenerateContent: function () {
                var controller = this,
                    flashMessages = this.get('controllers.flash-messages'),
                    store = this.get('store'),
                    model = this.get('model'),
                    thingTypeName = model.constructor.typeKey,
                    adapter = store.getDynamicAdapter(thingTypeName),
                    url = adapter.buildURL(model.constructor.typeKey, model.get('id')),
                    promise = adapter.ajax(url + 'generate_content/?force=true', 'POST');

                promise.then(function (res) {
                    var msg,
                        msgStatus;
                    if (res[thingTypeName].status === 'CALLED') {
                        msg = 'Content request for "' + model.get('name') + '" has been succesfully scheduled.';
                        msgStatus = 'success';
                    } else if (res[thingTypeName].status === 'NOT_CALLED') {
                        msgStatus = 'warning';
                        msg = Ember['default'].View.create({
                            controller: controller,
                            tagName: 'span',
                            template:  Ember['default'].Handlebars.compile('There is already content for "' + model.get('name') + '". Maybe you want to <a {{action "forceGenerateContent"}}>force regeneration</a>?')
                        });
                    }
                    flashMessages.addMessage(msg, msgStatus);
                    controller.hideLoading('generateContent');
                    flashMessages.now();
                }, function (e) {
                    controller.hideLoading('generateContent');
                    Raven.captureMessage('Error regenerating Content!', e);
                });
            },

            edit: function () {
                this.hideLoading('edit');
                this.transitionToRoute('content-project.thing-type.thing.edit', this.get('model.id'));
            },
            "delete": function () {
                this.hideLoading('edit');
                this.transitionToRoute('content-project.thing-type.thing.delete', this.get('model.id'));
            },

            reportJiraIssue: function () {
                this.reportJiraIssue();
            }
        }
    });

});
define('morgana/controllers/content-project/thing-type/thing/server-side-model-field-detail', ['exports', 'ember'], function (exports, Ember) {

	'use strict';

	exports['default'] = Ember['default'].Controller.extend({
	});

});
define('morgana/controllers/content-projects/index', ['exports', 'ember', 'morgana/mixins/pagination'], function (exports, Ember, pagination) {

    'use strict';

    exports['default'] = Ember['default'].ArrayController.extend(pagination.PaginationMixin, {
        model: Ember['default'].A(),
        itemObjectName: 'contentProject',
        itemsPerPage: 30,
        meta: Ember['default'].computed('model', function () {
            return this.store.metadataFor("contentProject");
        }),

        actions: {
            createContentProject: function () {
                this.transitionToRoute('engine-configurations');
            },
            contentProjectDetail: function (contentProject) {
                this.transitionToRoute('content-project.index', contentProject.get('id'));
            }
        }
    });

});
define('morgana/controllers/credits/credit-history-element', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend({

        model: null,

        isAdd: Ember['default'].computed('model.operation', function() {
            return this.get('model.operation') === 'add';
        })
    });

});
define('morgana/controllers/credits/credit-history', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].ArrayController.extend({
        itemController: 'credits/creditHistoryElement'
    });

});
define('morgana/controllers/credits/invoices', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].ArrayController.extend({
        actions: {
            downloadInvoice: function (invoice) {
                var url = '/dashboard/invoice/' + invoice.get('id');
                window.location.href = url;
            }
        }
    });

});
define('morgana/controllers/download-exports/index', ['exports', 'ember', 'morgana/config/environment', 'morgana/mixins/pagination', 'morgana/mixins/permissions'], function (exports, Ember, ENV, pagination, permissions) {

    'use strict';

    exports['default'] = Ember['default'].ArrayController.extend(pagination.PaginationMixin, permissions.PermissionsMixin, {
        model: Ember['default'].A(),
        itemObjectName: 'contentProjectExport',
        itemsPerPage: 10,

        meta: Ember['default'].computed('model', function () {
            return this.store.metadataFor("contentProjectExport");
        }),

        actions: {
            toContentProjects: function () {
                this.transitionToRoute('home');
            },
            toTags: function () {
                this.transitionToRoute('tags');
            },
            'downloadFile': function (contentProjectExport) {
                var store = this.get('store'),
                    url = contentProjectExport.get('downloadUrl');

                if (url) {
                    window.location.href = '' + ENV['default'].restAdapter.host + url;
                    // FIXME: add some error handling
                }
            }
        }
    });

});
define('morgana/controllers/engine-configuration/content-project/new', ['exports', 'ember', 'morgana/mixins/flash-message', 'morgana/mixins/server-side-field-error'], function (exports, Ember, FlashMessageMixin, ServerSideFieldErrorMixin) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(FlashMessageMixin['default'], ServerSideFieldErrorMixin['default'], {
        actions: {
            back: function () {
                this.hideLoading('back');
                this.transitionToRoute('engine-configuration');
            },
            create: function () {
                var controller = this;

                controller.get('model').save().then(function (contentProject) {
                    controller.addSuccessMessage('Content Project created.');
                    controller.hideLoading('create');
                    controller.transitionToRoute('content-project.index', contentProject.get('id'));
                }, function (e) {
                    controller.hideLoading('create');
                    controller.handleServerSideError('Error creating Content Project!', e);
                });
            }
        }
    });

});
define('morgana/controllers/engine-configuration/index', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend({
        actions: {
            back: function () {
                this.transitionToRoute('engine-configurations');
            },
            createContentProject: function () {
                this.transitionToRoute('engine-configuration.content-project.new');
            }
        }
    });

});
define('morgana/controllers/engine-configurations/contact', ['exports', 'ember', 'morgana/mixins/flash-message'], function (exports, Ember, FlashMessageMixin) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(FlashMessageMixin['default'], {
        actions: {
            back: function () {
                this.hideLoading('back');
                this.transitionToRoute('engine-configurations');
            },
            create: function () {
                var flashMessages = this.get('controllers.flash-messages'),
                    controller = this,
                    contact = this.get('model');
                contact.save().then(function () {
                    flashMessages.addMessage('Your message has been sent.', 'success');
                    controller.hideLoading('create');
                    controller.transitionToRoute('home');

                }, function (e) {
                    controller.hideLoading('create');
                    Raven.captureMessage('Error creating Contact for Engine Configuration!', e);
                });
            }
        }
    });

});
define('morgana/controllers/engine-configurations/index', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].ArrayController.extend({
        myFilter: '',

        allLanguages: Ember['default'].computed(function () {
            return this.get('store').find('Language');
        }),

        allEngineConfigurationStatus: Ember['default'].computed(function () {
            return this.get('store').find('EngineConfigurationStatus');
        }),

        allEngineContentTypeCategories: Ember['default'].computed(function () {
            return this.get('store').find('EngineContentTypeCategory');
        }),


        filteredContent: [],

        _filterProperty: function (filterPropertyName, allFilterOptionsPropName) {
            var self = this,
                selectedOptions = self.get(allFilterOptionsPropName).filterBy('checked', true),
                engineConfigurations = self.get('arrangedContent'),
                propertyIsFiltered = selectedOptions.length > 0;

            engineConfigurations.forEach(function (engineConfiguration) {
                var filters = engineConfiguration.get('filters'),
                    filterPropertyIdx = filters.indexOf(filterPropertyName);

                if (!propertyIsFiltered) {
                    //show all
                    if (filterPropertyIdx > -1) {
                        filters.splice(filterPropertyIdx, 1);
                        engineConfiguration.set('filters', filters);
                        self.filterContent();
                    }
                } else {
                    engineConfiguration.get(filterPropertyName).then(function (filterProperty) {

                        if (selectedOptions.indexOf(filterProperty) > -1) {
                            if (filterPropertyIdx > -1) {
                                filters.splice(filterPropertyIdx, 1);
                                engineConfiguration.set('filters', filters);
                                self.filterContent();
                            }
                        } else {
                            if (filterPropertyIdx === -1) {
                                filters.push(filterPropertyName);
                                engineConfiguration.set('filters', filters);
                                self.filterContent();
                            }
                        }

                    });
                }
            });
        },


        filterLanguages: Ember['default'].observer('allLanguages.@each.checked', function () {
            this._filterProperty('language', 'allLanguages');
        }),

        filterCategories: Ember['default'].observer('allEngineContentTypeCategories.@each.checked', function () {
            this._filterProperty('engineContentTypeCategory', 'allEngineContentTypeCategories');
        }),

        filterStatus: Ember['default'].observer('allEngineConfigurationStatus.@each.checked', function () {
            this._filterProperty('status', 'allEngineConfigurationStatus');
        }),


        filterContent: Ember['default'].observer('myFilter', 'arrangedContent', function () {
            var myFilter = this.get('myFilter'),
                engineConfigurations = this.get('arrangedContent'),
                filterRegExp;

            engineConfigurations = engineConfigurations.filter(function (engineConfiguration) {
                return engineConfiguration.get('filters').length === 0;
            });

            if (myFilter) {
                filterRegExp = new RegExp(myFilter, 'gi');
                engineConfigurations = engineConfigurations.filter(function (engineConfiguration) {
                    return engineConfiguration.get('descriptiveName').match(filterRegExp) || engineConfiguration.get('thingType').match(filterRegExp);
                });
            }

            this.set('filteredContent', engineConfigurations);

        }),

        actions: {
            back: function () {
                this.transitionToRoute('home');
            }
        }


    });

});
define('morgana/controllers/eventlog/index', ['exports', 'ember', 'morgana/mixins/pagination'], function (exports, Ember, pagination) {

    'use strict';

    exports['default'] = Ember['default'].ArrayController.extend(pagination.PaginationMixin, {

        itemObjectName: 'eventlog',
        itemsPerPage: 30,
        meta: Ember['default'].computed('model', function () {
            return this.store.metadataFor("eventlog");
        }),
        init: function () {
            this._super();
            this.sortFields = Ember['default'].A();
            this.sortFields.push(pagination.PaginationSortField.create({
                name: 'created',
                sortDirection: 'DESC'
            }));
        }
    });

});
define('morgana/controllers/flash-messages', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Controller.extend({
        queuedMessages: Ember['default'].A(),
        currentMessages: Ember['default'].A(),

        messages: Ember['default'].computed.alias('currentMessages'),

        hasMessages: Ember['default'].computed('messages', function () {
            return this.get('messages').length > 0;
        }),

        now: function () {
            this.setProperties({
                queuedMessages: Ember['default'].A(),
                currentMessages: this.get('queuedMessages')
            });
        },

        actions: {
            dismissFlashMessage: function (messageObj) {
                this.get('currentMessages').removeObjects(this.get('currentMessages').filterBy('text', messageObj.get('text')).filterBy('type', messageObj.get('type')));
            }
        },

        pushMessage: function (messageObject) {
            this.get('queuedMessages').addObject(messageObject);
        },

        clearQueue: function () {
            this.set('queuedMessages', Ember['default'].A());
        },

        clearCurrent: function () {
            this.set('currentMessages', Ember['default'].A());
        },

        addMessage: function (message, messageType) {
            var messageObject = Ember['default'].Object.create({
                text: message,
                messageType: messageType
            });

            this.pushMessage(messageObject);
        }
    });

});
define('morgana/controllers/home/index', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Controller.extend({
        needs: ['application'],

        model: Ember['default'].computed(function () {
            return this.get('controllers.application').get('currentUser');
        }),

        currentUser: Ember['default'].computed('model', function () {
            return this.get('model');
        }),

        actions: {
            addContentProject: function () {
                this.transitionToRoute('engine-configurations');
            },
            creditOverview: function () {
                this.transitionToRoute('credits');
            }
        }
    });

});
define('morgana/controllers/login', ['exports', 'ember', 'simple-auth/mixins/login-controller-mixin'], function (exports, Ember, LoginControllerMixin) {

    'use strict';

    exports['default'] = Ember['default'].Controller.extend(LoginControllerMixin['default'], {
        authenticator: 'authenticator:myax'
    });

});
define('morgana/controllers/navigation', ['exports', 'ember', 'morgana/mixins/permissions'], function (exports, Ember, permissions) {

    'use strict';

    exports['default'] = Ember['default'].Controller.extend(permissions.PermissionsMixin, {
        currentUser: Ember['default'].computed.alias('session.currentUser'),

        actions: {
            invalidateSession: function () {
                this.get('session').invalidate();
            }
        }
    });

});
define('morgana/controllers/profile/edit-company', ['exports', 'ember', 'morgana/mixins/flash-message', 'morgana/mixins/server-side-model-fields', 'morgana/mixins/server-side-field-error'], function (exports, Ember, FlashMessageMixin, ServerSideModelFieldsMixin, ServerSideFieldErrorMixin) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(ServerSideFieldErrorMixin['default'], ServerSideModelFieldsMixin['default'], FlashMessageMixin['default'], {

        actions: {
            edit: function () {
                var controller = this,
                    model = this.get('model');

                model.save().then(function () {
                    controller.addSuccessMessage('Organization saved.');
                    controller.hideLoading('edit');
                    controller.transitionToRoute('profile.index');
                }, function (e) {
                    controller.hideLoading('edit');
                    controller.handleServerSideError('Error editing Organization!', e);
                });
            },
            back: function () {
                this.get('model').rollback();
                this.hideLoading('back');
                this.transitionToRoute('profile.index');
            }
        }
    });

});
define('morgana/controllers/profile/edit-user', ['exports', 'ember', 'morgana/mixins/flash-message', 'morgana/mixins/server-side-model-fields', 'morgana/mixins/server-side-field-error'], function (exports, Ember, FlashMessageMixin, ServerSideModelFieldsMixin, ServerSideFieldErrorMixin) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(ServerSideFieldErrorMixin['default'], ServerSideModelFieldsMixin['default'], FlashMessageMixin['default'], {

        actions: {
            edit: function () {
                var controller = this,
                    model = this.get('model');

                model.save().then(function () {
                    controller.addSuccessMessage('User saved.');
                    controller.hideLoading('edit');
                    controller.transitionToRoute('profile.index');
                }, function (e) {
                    controller.hideLoading('edit');
                    controller.handleServerSideError('Error editing User!', e);
                });
            },
            back: function () {
                this.get('model').rollback();
                this.hideLoading('back');
                this.transitionToRoute('profile.index');
            }
        }
    });

});
define('morgana/controllers/profile/index', ['exports', 'ember', 'morgana/mixins/server-side-model-fields'], function (exports, Ember, ServerSideModelFieldsMixin) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(ServerSideModelFieldsMixin['default'], {

        currentUser: Ember['default'].computed.alias('session.currentUser'),

        actions: {
            editCompany: function () {
                this.hideLoading('editCompany');
                this.transitionToRoute('profile.edit-company');
            },
            editUser: function () {
                this.hideLoading('editUser');
                this.transitionToRoute('profile.edit-user');
            }
        }
    });

});
define('morgana/controllers/tags/index', ['exports', 'ember', 'morgana/mixins/pagination', 'morgana/mixins/permissions', 'morgana/adapters/application', 'morgana/mixins/flash-message'], function (exports, Ember, pagination, permissions, ApplicationAdapter, FlashMessageMixin) {

    'use strict';

    exports['default'] = Ember['default'].ArrayController.extend(pagination.PaginationMixin, FlashMessageMixin['default'], permissions.PermissionsMixin, {
        model: Ember['default'].A(),
        useFacets: true,
        itemObjectName: 'thing',
        itemsPerPage: 30,
        meta: Ember['default'].computed('model', function () {
            return this.store.metadataFor("thing");
        }),

        itemController: 'tags/thingRequirementLevelDetail',

        facetModelMaps: {
            'content_project_pk': {
                modelName: 'contentProject',
                modelKeyForName: 'name'
            },
            'status': {

            },
            'tag': {

            },
            'most_important_missing_requirement_level': {
                modelName: 'requirementLevelStatus',
                modelKeyForName: 'statusName'
            }

        },

        facetFilterContentProject: null,
        facetFilterContentProjects: function () {
            return this.get('facetFilters').filter(function (facetFilter) {
                return facetFilter.get('facetName') === 'content_project_pk' && facetFilter.get('active');
            });
        }.property('facetFilters.@each.active'),

        facetFilterContentProjectObserver: Ember['default'].observer('facetFilterContentProject', function () {
            this.handleFacetFilter('content_project_pk', 'facetFilterContentProject', 'facetFilterContentProjects');
        }),


        facetFilterTag: null,
        facetFilterTags: function () {
            return this.get('facetFilters').filter(function (facetFilter) {
                return facetFilter.get('facetName') === 'tag' && facetFilter.get('active');
            });
        }.property('facetFilters.@each.active'),
        facetFilterTagObserver: Ember['default'].observer('facetFilterTag', function () {
            this.handleFacetFilter('tag', 'facetFilterTag', 'facetFilterTags');
        }),

        facetFilterStatus: null,
        facetFilterStatus_: function () {
            return this.get('facetFilters').filter(function (facetFilter) {
                return facetFilter.get('facetName') === 'status' && facetFilter.get('active');
            });
        }.property('facetFilters.@each.active'),
        facetFilterStatusObserver: Ember['default'].observer('facetFilterStatus', function () {
            this.handleFacetFilter('status', 'facetFilterStatus', 'facetFilterStatus_');
        }),

        facetFilterValidity: null,
        facetFilterValidities: function () {
            return this.get('facetFilters').filter(function (facetFilter) {
                return facetFilter.get('facetName') === 'most_important_missing_requirement_level' && facetFilter.get('active');
            });
        }.property('facetFilters.@each.active'),
        facetFilterValidityObserver: Ember['default'].observer('facetFilterValidity', function () {
            this.handleFacetFilter('most_important_missing_requirement_level', 'facetFilterValidity', 'facetFilterValidities');
        }),

        init: function () {
            this._super();
            this.sortFields = Ember['default'].A();
            this.sortFields.push(pagination.PaginationSortField.create({
                name: 'uid',
                sortDirection: 'ASC'
            }));
            this.sortFields.push(pagination.PaginationSortField.create({
                name: 'sku'
            }));
            this.sortFields.push(pagination.PaginationSortField.create({
                name: 'name'
            }));
            this.sortFields.push(pagination.PaginationSortField.create({
                name: 'content_project_pk'
            }));
            this.sortFields.push(pagination.PaginationSortField.create({
                name: 'tag'
            }));
            this.sortFields.push(pagination.PaginationSortField.create({
                name: 'most_important_missing_requirement_level'
            }));
            this.sortFields.push(pagination.PaginationSortField.create({
                name: 'status'
            }));
            this.sortFields.push(pagination.PaginationSortField.create({
                name: 'text_length_in_chars'
            }));
            this.sortFields.push(pagination.PaginationSortField.create({
                name: 'modified'
            }));
        },

        actions: {

            home: function () {
                this.transitionToRoute('home.index');
            },

            thingDetail: function (thing) {
                var controller = this;
                thing.get('contentProject').then(function (contentProject) {
                    controller.transitionToRoute('content-project.thing-type.thing.index', contentProject.get('id'), thing.get('id'));
                });

            },
            sortField: function (fieldName) {
                this.sortByField(fieldName);
            },
            searchFields: function () {
                this.searchFields();
            },

            uploadFile: function () {
                this.transitionToRoute('tags.upload');
            },

            generateContent: function () {
                var controller = this,
                    flashMessages = this.get('controllers.flash-messages'),
                    store = this.get('store'),
                    adapter = ApplicationAdapter['default'].create(),
                    urlParams = controller._buildUrlParams(),
                    url = adapter.buildURL() + 'generate-content/?' + Ember['default'].$.param(urlParams);

                adapter.ajax(url, 'POST').then(function (res) {
                    var responseContent = res,
                        msg,
                        msgStatus;
                    if (responseContent.status === 'CALLED') {
                        msg = 'Content requests for Objects have been successfully scheduled.';
                        msgStatus = 'success';
                    } else if (responseContent.status === 'NOT_CALLED') {
                        msgStatus = 'warning';
                        msg = Ember['default'].View.create({
                            controller: controller,
                            tagName: 'span',
                            template: Ember['default'].Handlebars.compile('There is already content for all Objects. Maybe you want to <a {{action "forceGenerateContent"}}>force regeneration</a>?')
                        });
                    }
                    controller.hideLoading('generateContent');
                    flashMessages.addMessage(msg, msgStatus);
                    flashMessages.now();
                }, function (e) {
                    var msgStatus,
                        msg;

                    if (e && e.message) {
                        msgStatus = 'error';
                        msg = Ember['default'].View.create({
                            controller: controller,
                            tagName: 'span',
                            template: Ember['default'].Handlebars.compile(e.message)
                        });
                        flashMessages.addMessage(msg, msgStatus);
                        flashMessages.now();
                    } else {
                        Raven.captureMessage('Error generating Content!', e);
                    }
                    controller.hideLoading('generateContent');
                });
            },

            forceGenerateContent: function () {
                var controller = this,
                    flashMessages = this.get('controllers.flash-messages'),

                    adapter = ApplicationAdapter['default'].create(),
                    urlParams = controller._buildUrlParams({force: true}),
                    url = adapter.buildURL() + 'generate-content/?' + Ember['default'].$.param(urlParams);

                adapter.ajax(url, 'POST').then(function (res) {
                    var responseContent = res,
                        msg,
                        msgStatus;
                    if (responseContent.status === 'CALLED') {
                        msg = 'Content requests for Objects have been successfully scheduled.';
                        msgStatus = 'success';
                    } else if (responseContent.status === 'NOT_CALLED') {
                        msgStatus = 'error';
                        msg = 'Sorry, an error occured. This should not have happened';
                        Raven.captureMessage('Error generating Content! Force returned NOT_CALLED', res);
                    }
                    controller.hideLoading('generateContent');
                    flashMessages.addMessage(msg, msgStatus);
                    flashMessages.now();
                }, function (e) {
                    var msgStatus,
                        msg;
                    if (e && e.message) {
                        msgStatus = 'error';
                        msg = Ember['default'].View.create({
                            controller: controller,
                            tagName: 'span',
                            template: Ember['default'].Handlebars.compile(e.message)
                        });
                        flashMessages.addMessage(msg, msgStatus);
                        flashMessages.now();
                    } else {
                        Raven.captureMessage('Error generating Content!', e);
                    }
                    controller.hideLoading('generateContent');
                });

            },

            downloadContent: function () {
                var controller = this,
                    flashMessages = this.get('controllers.flash-messages'),

                    adapter = ApplicationAdapter['default'].create(),
                    urlParams = controller._buildUrlParams({force: true}),
                    url = adapter.buildURL() + 'generate-export/?' + Ember['default'].$.param(urlParams);

                adapter.ajax(url, 'POST').then(function (res) {
                    var responseContent = res,
                        msg,
                        msgStatus;
                    if (responseContent.status === 'CALLED') {
                        msg = 'Your download will be generated. It will be available here shortly. (You might need to refresh this page, though)';
                        msgStatus = 'success';
                        flashMessages.addMessage(msg, msgStatus);
                        controller.transitionToRoute('download-exports');
                    } else if (responseContent.status === 'NOT_CALLED') {
                        msgStatus = 'error';
                        msg = 'A Download could not be generated.';
                        Raven.captureMessage('Error generating Download!', res);
                        flashMessages.addMessage(msg, msgStatus);
                        flashMessages.now();
                    }

                }, function (e) {
                    var msgStatus,
                        msg;
                    if (e && e.message) {
                        msgStatus = 'error';
                        msg = Ember['default'].View.create({
                            controller: controller,
                            tagName: 'span',
                            template: Ember['default'].Handlebars.compile(e.message)
                        });
                        flashMessages.addMessage(msg, msgStatus);
                        flashMessages.now();
                    } else {
                        Raven.captureMessage('Error generating Download!', e);
                    }
                });

            },

            buyCredits: function () {
                this.hideLoading('buyCredits');
                this.transitionToRoute('credits');
            }

        }
    });

});
define('morgana/controllers/tags/thing-requirement-level-detail', ['exports', 'ember', 'morgana/mixins/server-side-model-fields', 'morgana/mixins/permissions', 'morgana/models/thing'], function (exports, Ember, ServerSideModelFieldsMixin, permissions, ThingModel) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(ServerSideModelFieldsMixin['default'], permissions.PermissionsMixin, {

        isLoading: null,

        model: null,
        serverSideModelFieldsModel: Ember['default'].computed('concreteThing', function () {
            return this.get('concreteThing');
        }),


        concreteThing: null,
        showDetails: false,
        showDetailsLoading: false,

        hasDetails: Ember['default'].computed('model.mostImportantMissingRequirementLevel', function () {
            return parseInt(this.get('model.mostImportantMissingRequirementLevel'), 10) > 0;
        }),

        actions: {
            thingRequirementLevelDetail: function () {
                this.set('showDetails', true);
                if (this.get('concreteThing')) {
                    return;
                }

                this.set('showDetailsLoading', true);
                this.loadConcreteThing();
            }
        },


        loadConcreteThing: function () {
            var concreteThingPromise,
                controller = this,
                store = controller.get('store'),
                model = controller.get('model'),
                contentProject = model.get('contentProject');

            contentProject.then(function (contentProject) {


                concreteThingPromise = new Ember['default'].RSVP.Promise(function (resolve, reject) {
                    contentProject.get('engineConfiguration').then(function (engineConfiguration) {
                        var thingType = engineConfiguration.get('thingType'),
                            thingAdapter = store.getDynamicAdapter(thingType),
                            ret = {};
                        thingAdapter.reopen({
                            pathForType: function (type) {
                                return 'content-project/' + contentProject.get('id') + '/thing';
                            }
                        });

                        ret = store.getDynamicModel(thingType, ThingModel['default']).then(function () {
                            return store.find(thingType, model.get('id'));
                        });
                        resolve(ret);
                    });
                });
                concreteThingPromise.then(function (concreteThing) {
                    controller.set('concreteThing', concreteThing);
                    controller.set('showDetailsLoading', false);
                });

            });
        }

    });

});
define('morgana/controllers/tags/upload', ['exports', 'ember', 'morgana/mixins/flash-message', 'morgana/mixins/server-side-field-error', 'morgana/mixins/permissions'], function (exports, Ember, FlashMessageMixin, ServerSideFieldErrorMixin, permissions) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(FlashMessageMixin['default'], ServerSideFieldErrorMixin['default'], permissions.PermissionsMixin, {


        actions: {
            upload: function () {
                var controller = this,
                    bulkupload = this.get('model');

                bulkupload.save().then(function (bulkupload) {
                    controller.addSuccessMessage('File successfully uploaded.  It will take a second for the new data to be shown.');
                    controller.hideLoading('upload');
                    controller.transitionToRoute('tags.index');
                }, function (e) {
                    controller.handleServerSideError('Error uploading file!', e);
                    controller.hideLoading('upload');
                });
            },
            back: function () {
                var controller = this,
                    bulkupload = this.get('model');
                bulkupload.deleteRecord();
                controller.hideLoading('back');
                controller.transitionToRoute('tags.index');
            }
        }
    });

});
define('morgana/controllers/things/index', ['exports', 'ember', 'morgana/mixins/pagination'], function (exports, Ember, pagination) {

    'use strict';

    exports['default'] = Ember['default'].ArrayController.extend(pagination.PaginationMixin, {

        itemObjectName: 'thing',

        contentProject: null,
        itemsPerPage: 30,
        meta: Ember['default'].computed('model', function () {
            return this.store.metadataFor("thing");
        }),

        init: function () {
            this._super();
            this.sortFields = Ember['default'].A();
            this.sortFields.push(pagination.PaginationSortField.create({
                name: 'uid',
                sortDirection: 'ASC'
            }));
            this.sortFields.push(pagination.PaginationSortField.create({
                name: 'name'
            }));
        },

        actions: {
            thingDetail: function (thing) {
                var controller = this,
                    contentProject = this.get('contentProject');
                controller.transitionToRoute('content-project.thing-type.thing.index', contentProject.get('id'), thing.get('id'));
            },


            sortField: function (fieldName) {
                this.sortByField(fieldName);
            },
            searchFields: function () {
                this.searchFields();
            }
        }
    });

});
define('morgana/controllers/user-check-list/index', ['exports', 'ember', 'morgana/mixins/permissions'], function (exports, Ember, permissions) {

    'use strict';

    exports['default'] = Ember['default'].ObjectController.extend(permissions.PermissionsMixin, {
        model: {},

        actions: {
            addContentProject: function () {
                this.transitionToRoute('engine-configurations');
            },
            editProfile: function () {
                window.location.href = '/my_profile/';
            }
        }
    });

});
define('morgana/helpers/can-do', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports.canDo = canDo;

  function canDo (input) {
    return input;
  }

  exports['default'] = function (permissionName, options) {
      return Ember['default'].Handlebars.helpers.boundIf.call(this, 'permissions.' + permissionName, options);
  }

});
define('morgana/helpers/capitalize-string', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports.capitalizeString = capitalizeString;

    function capitalizeString(value) {
        return Ember['default'].String.capitalize(value);
    }

    exports['default'] = Ember['default'].Handlebars.makeBoundHelper(capitalizeString);

});
define('morgana/helpers/field-detail', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports.fieldDetail = fieldDetail;

  function fieldDetail(value) {
    var fields = value.hash.fields,
          model = value.hash.model,
          rows = [],
          ret;

      fields.forEach(function (fieldData) {
          var fieldName = fieldData.fieldName,
              modelValue = model.get(fieldName),
              realModelValue,
              ecsapedValue,
              requirementLevel = parseInt(fieldData.requirement_level, 10) || 0,
              escapedLabel = Ember['default'].String.capitalize(Handlebars.Utils.escapeExpression(fieldData.label));

          if (fieldData.read_only) {
              return;
          }

          if (fieldData.type === 'field') {
              return;
          }

          if (modelValue && fieldData.type === 'choice') {
              realModelValue = modelValue.get('displayName');
          } else {
              realModelValue = modelValue;
          }

          ecsapedValue = Handlebars.Utils.escapeExpression(realModelValue);
          rows.push('<tr><th class="text-right">' + escapedLabel + '</th><td class="ax-field ax-field-level-' + requirementLevel + ' ax-field-' + (realModelValue ? 'not-' : '') + 'empty notranslate">' + ecsapedValue + '</td></tr>');
      });

      ret = new Ember['default'].Handlebars.SafeString('<table><tbody>' + rows.join('') + '</tbody></table>');

      return ret;
  }

  exports['default'] = Ember['default'].Handlebars.makeBoundHelper(fieldDetail);

});
define('morgana/helpers/flash-messages', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports.flashMessages = flashMessages;

    function flashMessages(input) {
        return input;
    }

    exports['default'] = function (options) {
        var template = options.fn,
            container = options.data.keywords.controller.container,
            controller = container.lookup('controller:flash-messages'),
            parent = Ember['default'].ContainerView.extend({
                hideAndShowMessage: Ember['default'].observer('controller.currentMessages', function () {
                    var currentMessages = this.get('controller.currentMessages'),
                        view;

                    if (currentMessages) {
                        view = Ember['default'].View.create({
                            template: template
                        });
                    }

                    this.set('currentView', view);
                })
            });

        options.hash.controller = controller;
        options.hashTypes = options.hashTypes || {};
        Ember['default'].Handlebars.helpers.view.call(this, parent, options);
    }

});
define('morgana/helpers/pluralize-string', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports.pluralizeString = pluralizeString;

    function pluralizeString(number, opts) {
        var single = opts.hash['s'];
        Ember['default'].assert('pluralize requires a singular string (s)', single);
        var plural = opts.hash['p'] || single + 's';
        return (number === 1) ? single : plural;
    }

    exports['default'] = Ember['default'].Handlebars.makeBoundHelper(pluralizeString);

});
define('morgana/helpers/text-with-errors', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports.textWithErrors = textWithErrors;

  function textWithErrors(text, options) {
    var $ = Ember['default'].$,
          errors = options.hash.errors || [],
          x = 0,
          y = 0,
          addedNodes = 0,
          $text = $('<p></p>').text(text);

      $.each(errors, function (index, error) {
          var textNode,
              textContent,
              prefix,
              wrong,
              suffix,
              tooltip,
              $span = $('<span class="languagetool-error languagetool-rule-' + error.ruleId + '"></span>');

          if (y < error.fromy) {
              x = 0;
              y = error.fromy;
          }

          textNode = $text.contents()[addedNodes + 2 * error.fromy];

          if (!textNode) {
              return; // FIXME: just a hotfix this way.
          }

          textContent = textNode.textContent;
          prefix = textContent.slice(0, error.fromx - x);
          wrong = textContent.slice(error.fromx - x, error.tox - x);
          suffix = textContent.slice(error.tox - x);

          tooltip = error.msg;
          if (error.replacements.length) {
              tooltip += '\n\nSuggested replacements: "' + error.replacements.join('", "') + '"';
          }
          $span.attr('title', tooltip);
          $span.text(wrong);
          $(textNode).replaceWith([document.createTextNode(prefix), $span, document.createTextNode(suffix)]);
          x = error.tox;
          addedNodes += !!prefix.length + !!suffix.length;
      });

      return new Ember['default'].Handlebars.SafeString($text.html());
  }

  exports['default'] = Ember['default'].Handlebars.makeBoundHelper(textWithErrors);

});
define('morgana/initializers/ember-moment', ['exports', 'ember-moment/helpers/moment', 'ember-moment/helpers/ago', 'ember'], function (exports, moment, ago, Ember) {

  'use strict';

  var initialize = function(/* container, app */) {
    Ember['default'].Handlebars.helper('moment', moment.moment);
    Ember['default'].Handlebars.helper('ago', ago.ago);
  };

  exports['default'] = {
    name: 'ember-moment',

    initialize: initialize
  };

  exports.initialize = initialize;

});
define('morgana/initializers/export-application-global', ['exports', 'ember', 'morgana/config/environment'], function (exports, Ember, config) {

  'use strict';

  exports.initialize = initialize;

  function initialize(container, application) {
    var classifiedName = Ember['default'].String.classify(config['default'].modulePrefix);

    if (config['default'].exportApplicationGlobal && !window[classifiedName]) {
      window[classifiedName] = application;
    }
  };

  exports['default'] = {
    name: 'export-application-global',

    initialize: initialize
  };

});
define('morgana/initializers/flash-messages', ['exports', 'morgana/controllers/flash-messages'], function (exports, FlashMessagesController) {

  'use strict';

  exports.initialize = initialize;

  function initialize(container) {
      container.register('controller:flash-messages', FlashMessagesController['default']);
  }

  exports['default'] = {
    name: 'flash-messages',
    initialize: initialize
  };

});
define('morgana/initializers/myax', ['exports', 'morgana/authenticators/myax', 'morgana/authorizers/myax'], function (exports, Authenticator, Authorizer) {

  'use strict';

  exports.initialize = initialize;

  function initialize(container /* , application */) {
    // application.inject('route', 'foo', 'service:foo');
       container.register('authorizer:myax', Authorizer['default']);
      container.register('authenticator:myax', Authenticator['default']);
  }

  exports['default'] = {
      name: 'myax',
      before: 'simple-auth',
      initialize: initialize
  };

});
define('morgana/initializers/server-side-model', ['exports'], function (exports) {

  'use strict';

  exports.initialize = initialize;

  function initialize(container, application) {
      function registerModel (modelName, model) {
          application.register('model:' + modelName, model, {instantiate: false});
      }

      function registerAdapter (adapterName, adapter) {
          application.register('adapter:' + adapterName, adapter, {instantiate: true});
      }

      application.register('serverSideModel:modelRegistry', registerModel, {instantiate: false});
      application.inject('store', 'modelRegistry', 'serverSideModel:modelRegistry');

      application.register('serverSideModel:adapterRegistry', registerAdapter, {instantiate: false});
      application.inject('store', 'adapterRegistry', 'serverSideModel:adapterRegistry');

  }

  exports['default'] = {
    name: 'server-side-model',
    initialize: initialize
  };

});
define('morgana/initializers/simple-auth', ['exports', 'simple-auth/configuration', 'simple-auth/setup', 'morgana/config/environment'], function (exports, Configuration, setup, ENV) {

  'use strict';

  exports['default'] = {
    name:       'simple-auth',
    initialize: function(container, application) {
      Configuration['default'].load(container, ENV['default']['simple-auth'] || {});
      setup['default'](container, application);
    }
  };

});
define('morgana/mixins/django-rest-file-adapter', ['exports', 'ember'], function (exports, Ember) {

	'use strict';

	exports['default'] = Ember['default'].Mixin.create({
	});

});
define('morgana/mixins/flash-message', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Mixin.create({
        needs: ['flash-messages'],

        addErrorMessage: function (msg) {
            var flashMessages = this.get('controllers.flash-messages');
            flashMessages.addMessage(msg, 'error');
        },
        addSuccessMessage: function (msg) {
            var flashMessages = this.get('controllers.flash-messages');
            flashMessages.addMessage(msg, 'success');
        },

        showErrorMessage: function (msg) {
            var flashMessages = this.get('controllers.flash-messages');
            this.addErrorMessage(msg);
            flashMessages.now();
        },
        showSuccessMessage: function (msg) {
            var flashMessages = this.get('controllers.flash-messages');
            this.addSuccessMessage(msg);
            flashMessages.now();
        }
    });

});
define('morgana/mixins/flash-messages-route', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Mixin.create({
        flashMessage: function (message, messageType) {
            var controller = this.controllerFor('flashMessages'),
                messageObject = Ember['default'].Object.create({
                    text: message,
                    messageType: ''
                });
            if (messageType !== undefined) {
                messageObject.set('messageType', messageType);
            }
            controller.pushMessage(messageObject);

            return controller;
        },


        enter: function () {
            this._super.apply(this, arguments);
            var controller = this.controllerFor('flashMessages'),
                routeName = this.get('routeName'),
                target = this.get('router.router.activeTransition.targetName');

            // do not display message in loading route, wait until
            // any loading is done.
            if (routeName !== "loading" && routeName === target) {
                controller.now();
            }
        }
    });

});
define('morgana/mixins/jira-report', ['exports', 'ember', 'morgana/mixins/flash-message'], function (exports, Ember, FlashMessageMixin) {

    'use strict';

    exports['default'] = Ember['default'].Mixin.create({
        needs: ['application'],

        _showJiraCollectorDialog: function() {
            return;
        },

        _showJiraCollectorLoadError: function () {
            this.showErrorMessage('Loading the report form failed.');
            Raven.captureMessage('Error loading the jira collector form!');
        },

        _initJiraReport: function () {
            var self = this,
                $ = Ember['default'].$,
                currentUser = this.get('controllers.application').get('currentUser');

            return new Ember['default'].RSVP.Promise(function(resolve, reject) {
                currentUser.then(function (cu) {

                    window.ATL_JQ_PAGE_PROPS = window.ATL_JQ_PAGE_PROPS || {};
                    $.extend(window.ATL_JQ_PAGE_PROPS, {
                        fieldValues: {
                            fullname: cu.get('fullName'),
                            email: cu.get('email') || 'foo@example.com',
                            description: 'URL: ' + window.location.href + '\n\n'
                        }
                    });

                    $.ajax({
                        url: window.AX.jiraIssueCollector.config.scriptUrl, // TODO: assert that this is configured
                        type: "get",
                        cache: false,
                        dataType: "script",
                        success: function () {
                            return resolve();
                        },
                        error: function () {
                            return reject();
                        }
                    });
                });
            }, 'Jira: JiraIssueCollector load script');
        },

        reportJiraIssue: function () {
            var self = this,
                initJiraReport = self._initJiraReport();

            initJiraReport.then(
                function () {self.hideLoading('reportJiraIssue'); Ember['default'].run.scheduleOnce('actions', self, window.AX.jiraIssueCollector.triggerJiraCollectorDialog);},
                function () {self.hideLoading('reportJiraIssue'); self._showJiraCollectorLoadError();}

            );
        }

    });

});
define('morgana/mixins/loading-stages-controller', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Mixin.create({
        actionsLoadingStages: {},

        showLoading: function (actionName) {
            this.set('actionsLoadingStages.' + actionName, true);
        },
        hideLoading: function (actionName) {
            this.set('actionsLoadingStages.' + actionName, false);
        }
    });

});
define('morgana/mixins/loading-stages-route', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Mixin.create({

        setupController: function (controller, context) {
            controller.set('actionsLoadingStages', {});

            this._super(controller, context);
        }

    });

});
define('morgana/mixins/pagination', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    var PaginationMixin,
        PaginationSortField,
        PaginationFacetOption;

    exports.PaginationMixin = PaginationMixin = Ember['default'].Mixin.create({

        meta: {}, // you need to add meta from requests
        itemsPerPage: 10,
        itemObjectName: '', // name of the objects to query for
        selectedPage: 1,

        useFacets: false,
        facetModelMaps: {},


        notFound: true,
        isLoading: true,

        searchTerm: '',
        lastUsedSearchTerm: '',
        searchTermStartSearchAtLength: 0,
        loadingPromise: null,

        showSearchTermField: Ember['default'].computed('lastUsedSearchTerm', 'hasItems', function () {
            return this.get('hasItems') || this.get('lastUsedSearchTerm');
        }),

        sortFields: Ember['default'].A(),
        facetFilters: Ember['default'].A(),

        sortFieldData: Ember['default'].computed('sortFields.@each.asQueryParam', function () {
            var ret = {},
                sortFields = this.get('sortFields');

            sortFields.forEach(function (sortField) {
                ret[sortField.get('name')] = sortField;
            });

            return ret;
        }),

        sortParam: Ember['default'].computed('sortFields.@each.asQueryParam', function () {
            var sortStrings = [],
                activeSortFields = this.get('sortFields').rejectBy('asQueryParam', null);

            activeSortFields.forEach(function (field) {
                sortStrings.push(field.get('asQueryParam'));
            });

            return sortStrings.join(',');
        }),

        getFacetParams: function () {
            var $ = Ember['default'].$,
                facetParams = {},
                facetFilters;
            if (!this.get('useFacets')) {
                return facetParams;
            }

            facetFilters = this.get('facetFilters').filterBy('checked');

            facetFilters.forEach(function (facetFilter) {
                $.extend(facetParams, facetFilter.get('asQueryParam'));
            });

            return facetParams;
        },

        needs: ['application'],
        application: Ember['default'].computed.alias("controllers.application"),


        hasItems: Ember['default'].computed('totalItems', 'notFound', function () {
            return !this.get("notFound") && parseInt(this.get('totalItems'), 10) > 0;
        }),

        allPages: Ember['default'].computed('totalPages', function () {
            var totalPages = this.get('totalPages'),
                pages = [],
                i;

            for (i = 1; i <= totalPages; i++) {
                pages.push(i);
            }

            return pages;
        }),

        totalPages: Ember['default'].computed('totalItems', function () {
            return Math.ceil(this.get('totalItems') / this.get('itemsPerPage')) || 1;
        }),

        totalItems: Ember['default'].computed('meta.@each', function () {
            return this.get('meta').count || 0;
        }),

        currentPage: Ember['default'].computed('meta.@each', function () {
            return this.get('meta').page || 0;
        }),


        _buildUrlParams: function (params) {
            var controller = this,
                $ = Ember['default'].$,
                urlParams = {},
                sortParam = controller.get('sortParam'),
                facetParams = controller.getFacetParams(),
                searchTerm = controller.get('lastUsedSearchTerm'),
                searchTermStartSearchAtLength = controller.get('searchTermStartSearchAtLength');

            // facets
            $.extend(urlParams, facetParams);

            // sort
            if (sortParam) {
                urlParams.ordering = sortParam;
            }

            // search
            if (searchTerm.length >= searchTermStartSearchAtLength) {
                urlParams.search = searchTerm;
            }

            if (params) {
                // add whats given to this method (e.g. {page: 1})
                $.extend(urlParams, params);
            }

            return urlParams;
        },

        _loadPage: function (page) {
            var controller = this,
                params,
                searchTerm = controller.get('searchTerm'),
                paginationParams = {
                    page: page,
                    page_size: controller.get('itemsPerPage')
                },
                itemObjectName = controller.get('itemObjectName'),
                loadingPromise = controller.get('loadingPromise') || new Ember['default'].RSVP.Promise(function (resolve) {
                    resolve();
                });

            controller.set('lastUsedSearchTerm', searchTerm);

            params = controller._buildUrlParams(paginationParams);

            controller.set('loadingPromise', loadingPromise.then(function () {
                var prom;
                controller.set('isLoading', true);
                prom = controller.store.find(itemObjectName, params).then(
                    function (items) {
                        controller.set('notFound', false);
                        controller.set('isLoading', false);
                        return items;
                    },
                    function () {
                        controller.set('notFound', true);
                        controller.set('isLoading', false);
                        return [];
                    }
                );

                return prom;
            }));

            return controller.get('loadingPromise');
        },


        facetsObserver: Ember['default'].observer('model', function () {
            var controller = this,
                facetFilters = this.get('facetFilters'),
                itemObjectName = this.get('itemObjectName'),
                facetModelMaps = this.get('facetModelMaps'),
                aggregations = this.get('meta.aggregations');

            if (!this.get('useFacets') || !aggregations || !facetModelMaps) {
                return;
            }

            facetFilters.setEach('docCount', 0);


            Object.keys(facetModelMaps).forEach(function (facetFilterName) {
                var facetModelMap = facetModelMaps[facetFilterName],
                    aggregation = aggregations[facetFilterName] || {buckets: []},
                    buckets = aggregation.buckets || [];

                buckets.forEach(function (bucket) {
                    var facetFilter = facetFilters.find(function (item) {
                            return item.get('facetName') === facetFilterName && item.get('key') === bucket.key;
                        }),
                        displayName;

                    if (!facetFilter) {
                        if (facetModelMap.modelName) {
                            facetFilters.push(PaginationFacetOption.create({
                                key: bucket.key,
                                docCount: bucket.doc_count,
                                facetName: facetFilterName,
                                name: null
                            }));
                            controller.store.findById(facetModelMap.modelName, bucket.key).then(function (model) {

                                var displayName = model.get(facetModelMap.modelKeyForName),
                                    updateFacetFilter;

                                updateFacetFilter = facetFilters.find(function (item) {
                                    return item.get('facetName') === facetFilterName && item.get('key') === bucket.key;
                                });

                                if (updateFacetFilter) {
                                    updateFacetFilter.set('name', displayName);
                                } else {
                                    facetFilters.push(PaginationFacetOption.create({
                                        key: bucket.key,
                                        docCount: bucket.doc_count,
                                        facetName: facetFilterName,
                                        name: displayName
                                    }));
                                }


                                return;
                            });
                        } else {
                            displayName = bucket.key;
                            facetFilters.push(PaginationFacetOption.create({
                                key: bucket.key,
                                docCount: bucket.doc_count,
                                facetName: facetFilterName,
                                name: displayName
                            }));
                        }

                    } else {
    //                    facetFilter.set('active', true);
                        facetFilter.set('docCount', bucket.doc_count);
                    }
                });
            });


        }),

        // Better trigger manually for now
    //    searchTermObserver: Ember.observer('searchTerm', function () {
    //        var controller = this,
    //            page = 1, //always start at first page if searching
    //            searchTermStartSearchAtLength = controller.get('searchTermStartSearchAtLength'),
    //            searchTerm = controller.get('searchTerm');
    //
    //        if (!searchTerm.length || searchTerm.length >= searchTermStartSearchAtLength) {
    //
    //            controller._loadPage(1).then(function (items) {
    //                controller.set('selectedPage', page);
    //                controller.set('model', items);
    //            });
    //        }
    //
    //        return;
    //    }),

        // Better trigger manually for now
    //    sortParamObserver: Ember.observer('sortParam', function () {
    //        var controller = this,
    //            page = 1; //always start at first page if searching
    //
    //        controller._loadPage(page).then(function (items) {
    //            controller.set('selectedPage', page);
    //            controller.set('model', items);
    //        });
    //
    //    }),


        jumpToPage: Ember['default'].observer('selectedPage', function () {
            var self = this,
                page = this.get('selectedPage'),
                maxPage = this.get('totalPages'),
                minPage = 1;

            if (page > maxPage) {
                page = maxPage;
            } else if (page < minPage) {
                page = minPage;
            }

            if (page === this.get('currentPage')) {
                return;
            }

            this._loadPage(page).then(function (items) {
                self.set('model', items);
            });

        }),

        searchFields: function () {
            var controller = this,
                page = 1, //always start at first page if searching
                searchTermStartSearchAtLength = controller.get('searchTermStartSearchAtLength'),
                searchTerm = controller.get('searchTerm');

            if (!searchTerm.length || searchTerm.length >= searchTermStartSearchAtLength) {

                controller._loadPage(1).then(function (items) {
                    controller.set('selectedPage', page);
                    controller.set('model', items);
                    controller.hideLoading('searchFields');
                }, function (e) {
                    controller.hideLoading('searchFields');
                });
            }

            return;
        },


        handleFacetFilter: function (facetFilterName, facetFilterControllerPropertyName, allFacetsControllerPropertyName) {
            var facetFilterControllerProperty = this.get(facetFilterControllerPropertyName);
            var allFacetsControllerProperty = this.get(allFacetsControllerPropertyName).filter(function (facetFilter) {
                return facetFilter.get('facetName') === facetFilterName;
            });
            allFacetsControllerProperty.setEach('checked', false);

            if (facetFilterControllerProperty) {
                facetFilterControllerProperty.set('checked', true);
            }
            this.filterFacets();
        },

        filterFacets: function () {
            var controller = this,
                page = 1; //always start at first page if searching

            controller._loadPage(page).then(function (items) {
                controller.set('selectedPage', page);
                controller.set('model', items);
            });

            return;
        },


        sortByField: function (fieldName) {
            var controller = this,
                page = 1, //always start at first page if searching
                otherSortFields = this.get('sortFields').rejectBy('name', fieldName).rejectBy('sortDirection', null),
                sortFields = this.get('sortFields').filterBy('name', fieldName),
                sortField = sortFields ? sortFields.objectAt(0) : null;

            otherSortFields.forEach(function (otherSortField) {
                otherSortField.sortNone();
            });

            if (sortField) {
                sortField.sortNext();
            }

            controller._loadPage(page).then(function (items) {
                controller.set('selectedPage', page);
                controller.set('model', items);
            });
        },


        actions: {
            next: function () {
                var self = this,
                    next = this.get('meta.next');
                if (next) {

                    this._loadPage(next).then(function (items) {
                        self.set('selectedPage', next);
                        self.set('model', items);
                    });
                }
            },
            previous: function () {
                var self = this,
                    previous = this.get('meta.previous');
                if (previous) {
                    this._loadPage(previous).then(function (items) {
                        self.set('selectedPage', previous);
                        self.set('model', items);
                    });
                }
            }

        }

    });

    exports.PaginationFacetOption = PaginationFacetOption = Ember['default'].Object.extend({
        name: null,
        key: null,
        docCount: 0,
        facetName: null,
        displayName: Ember['default'].computed('name', 'docCount', function () {
            return this.get('name') + ' (' + this.get('docCount') + ')';
        }),
        asQueryParam: Ember['default'].computed('facetName', 'key', function () {
            var ret = {};
            ret[this.get('facetName')] = this.get('key');
            return ret;
        }),
        checked: false,
        active: Ember['default'].computed('docCount', function () {
            return this.get('docCount') > 0;
        })
    });

    exports.PaginationSortField = PaginationSortField = Ember['default'].Object.extend({
        name: null,
        sortDirection: null,

        asQueryParam: Ember['default'].computed('name', 'sortDirection', function () {
            var name = this.get('name'),
                underscoredName = Ember['default'].String.underscore(name),
                sortDirection = this.get('sortDirection'),
                queryParam = '';

            if (!name || sortDirection === null) {
                return null;
            }

            if (sortDirection === 'DESC') {
                queryParam += '-';
            }

            queryParam += underscoredName;

            return queryParam;

        }),

        sortAscending: function () {
            this.set('sortDirection', 'ASC');
        },

        sortDescending: function () {
            this.set('sortDirection', 'DESC');
        },

        sortNone: function () {
            this.set('sortDirection', null);
        },

        sortNext: function () {
            var currentSortDirection = this.get('sortDirection');
            if (currentSortDirection === null) {
                this.sortAscending();
            } else if (currentSortDirection === 'ASC') {
                this.sortDescending();
            } else {
                this.sortNone();
            }
        },

        cssClass: Ember['default'].computed('sortDirection', function () {
            var sortDirection = this.get('sortDirection');

            if (sortDirection === null) {
                return 'sort-none';
            }

            if (sortDirection === 'ASC') {
                return 'sort-asc';
            }

            if (sortDirection === 'DESC') {
                return 'sort-desc';
            }

        })
    });

});
define('morgana/mixins/permissions', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    var Permissions,
        Permission,
        PermissionsMixin;

    exports.Permissions = Permissions = Ember['default'].Object.extend({
        _perms: Ember['default'].A(),
        all: {},

        register: function (obj) {
            this._perms.removeObjects(this._perms.filterBy('name', obj.get('name')));
            this._perms.addObject(obj);
        },

        _all: Ember['default'].observer('_perms.[]', '_perms.@each.can', function () {
            var perms = {};
            this.get("_perms").forEach(function (obj) {
                perms[obj.get('name')] = obj.get('can');
            });
            this.all = perms;
        }),

        getPermission: function (identifier) {
            var ret = this._perms.filterBy('name', identifier);

            if (ret) {
                return ret.objectAt(0);
            } else {
                return Permission.create();
            }
        }

    }).create();

    exports.Permission = Permission = Ember['default'].Object.extend({
        content: null,
        can: false
    });

    exports.PermissionsMixin = PermissionsMixin = Ember['default'].Mixin.create({
        _permissions: Permissions._perms,
        permissions: Ember['default'].computed('_permissions.[]', '_permissions.@each.can', function () {
            return Permissions.all;
        })
    });

});
define('morgana/mixins/server-side-field-error', ['exports', 'ember', 'morgana/mixins/flash-message'], function (exports, Ember, FlashMessageMixin) {

    'use strict';

    exports['default'] = Ember['default'].Mixin.create(FlashMessageMixin['default'], {


        handleServerSideError: function handleServerSideError(errorMessage, errorData) {
             var $ = Ember['default'].$,
                 errorMessages = [],
                 verboseErrorMessages = [],
                 controller = this;

            if (!errorData || !errorData.responseJSON) {
                controller.reportServerSideFieldError([errorMessage, 'NO DATA PROVIDED']);
                controller.displayServerSideFieldError([errorMessage]);
                return;
            }

            $.each(errorData.responseJSON, function (modelName, modelErrors) {
                var modelErrorMessages = [];
                $.each(modelErrors, function (fieldName, messages) {
                    modelErrorMessages.push(Ember['default'].String.fmt('Error for field "%@": %@', controller._fieldNameToLabel(fieldName), messages.join(' ')));
                });

                errorMessages.push(Ember['default'].String.fmt('%@\n %@', errorMessage, modelErrorMessages.join('\n')));
                verboseErrorMessages.push(Ember['default'].String.fmt('[%@] errorMessage \n %@', modelName, errorMessage, modelErrorMessages.join('\n')));

            });

            controller.reportServerSideFieldError(verboseErrorMessages);
            controller.displayServerSideFieldError(errorMessages);

        },


        reportServerSideFieldError: function (errorMessages) {
            try {
                Raven.captureMessage('Server reported error', errorMessages.join('\n'));
            } catch (e) {
                console.log('Could not inform sentry about error');
            }
        },

        displayServerSideFieldError: function (errorMessages) {

           var controller = this,
               msg;

            msg = Ember['default'].View.create({
                controller: controller,
                tagName: 'p',
                template:  Ember['default'].Handlebars.compile(errorMessages.join('\n').replace(/\n/g, '<br />'))
            });

            controller.showErrorMessage(msg);

        },



        _fieldNameToLabel: function (fieldName) {
            return Ember['default'].String.capitalize(Ember['default'].String.underscore(fieldName).replace('_', ''));
        }

    });

});
define('morgana/mixins/server-side-model-adapter', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Mixin.create({

        useUpdateFieldsForDynamicModels: false,
         /**
         Called by the store in order to fetch a JSON array for all
         of the records fields for a given type.
         The `findAll` method makes an Ajax (HTTP OPTIONS) request to a URL computed by `buildURL`, and returns a
         promise for the resulting payload.
         @private
         @method findFields
         @param {DS.Store} store
         @param {subclass of DS.Model} type
         @param {String} overwriteUrl
         @return {Promise} promise
         */
        findFields: function (store, type) {
            var url = this.buildURL(type.typeKey, this.get('useUpdateFieldsForDynamicModels'));
            return this.ajax(url, 'OPTIONS');
        }
    });

});
define('morgana/mixins/server-side-model-fields', ['exports', 'ember', 'morgana/models/field-requirement-level-data'], function (exports, Ember, FieldRequirementLevelModel) {

    'use strict';

    exports['default'] = Ember['default'].Mixin.create({

        serverSideModelFieldsModel: Ember['default'].computed('model', function () {
            return this.get('model');
        }),

        fields: Ember['default'].computed('serverSideModelFieldsModel', function () {
            return this.get('serverSideModelFieldsModel').constructor._fields.rejectBy('read_only').rejectBy('type', 'field');
        }),


        mainFields: Ember['default'].computed('fields', function () {
            return this.get('fields').filter(function (field) {
                return field.requirement_level > 0;
            });
        }),

        optionalFields: Ember['default'].computed('fields', function () {
            return this.get('fields').filter(function (field) {
                return field.requirement_level <= 0;
            });
        }),

        improvableFields: Ember['default'].computed('mainFields', 'serverSideModelFieldsModel', function () {
            var model = this.get('serverSideModelFieldsModel');
            return this.get('mainFields').filter(function (fieldData) {
                var fieldName = fieldData.fieldName,
                    modelValue = model.get(fieldName),
                    realModelValue;

                if (fieldData.read_only) {
                    return;
                }

                if (fieldData.type === 'field') {
                    return;
                }

                if (modelValue && fieldData.type === 'choice') {
                    realModelValue = modelValue.get('displayName');
                } else {
                    realModelValue = modelValue;
                }


                return !realModelValue;
            });
        }),


        improvableFieldsRequirementLevelData: Ember['default'].computed('improvableFields', 'serverSideModelFieldsModel', function () {
            return this._getRequirementLevelDataForFields(this.get('improvableFields'));
        }),
        optionalFieldsRequirementLevelData: Ember['default'].computed('optionalFields', 'serverSideModelFieldsModel', function () {
            return this._getRequirementLevelDataForFields(this.get('optionalFields'));
        }),
        mainFieldsRequirementLevelData: Ember['default'].computed('mainFields', 'serverSideModelFieldsModel', function () {
            return this._getRequirementLevelDataForFields(this.get('mainFields'));
        }),
        allFieldsRequirementLevelData: Ember['default'].computed('fields', 'serverSideModelFieldsModel', function () {
            return this._getRequirementLevelDataForFields(this.get('fields'));
        }),

        _getRequirementLevelDataForFields: function (fields) {
            var controller = this,
                model = this.get('serverSideModelFieldsModel'),
                fieldsRequirementLevelData = [];
            fields.forEach(function (fieldData) {
                var fieldName = fieldData.fieldName,
                    modelValue = model.get(fieldName),
                    realModelValue;

                if (modelValue && fieldData.type === 'choice') {
                    realModelValue = modelValue.get('displayName');
                } else {
                    realModelValue = modelValue;
                }

                fieldsRequirementLevelData.push(controller.get('store').createRecord('field-requirement-level-data', {
                    value: realModelValue,
                    label: fieldData.label,
                    requirementLevel: (parseInt(fieldData.requirement_level, 10) || 0)
                }));
            });

            return fieldsRequirementLevelData;
        }
    });

});
define('morgana/mixins/server-side-model-serializer', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Mixin.create({
        extractFindFields: function (store, type, payload) {
            var rawFields = payload[Object.keys(payload)[0]].actions.POST || payload[Object.keys(payload)[0]].actions.PUT,
                rawFieldsArray;

            rawFieldsArray = Ember['default'].$.map(rawFields, function (fieldData, fieldName) {
                if (fieldName === 'id') {
                    return;
                }
                fieldData.fieldName = Ember['default'].String.camelize(fieldName);
                fieldData.field_name = fieldName;
                return fieldData;
            });
            return rawFieldsArray;
        }
    });

});
define('morgana/mixins/server-side-model-store', ['exports', 'ember', 'ember-data', 'morgana/app', 'morgana/adapters/application', 'morgana/serializers/application', 'morgana/models/model-field-choice'], function (exports, Ember, DS, App, ApplicationAdapter, ApplicationSerializer, ModelFieldChoiceModel) {

    'use strict';

    exports['default'] = Ember['default'].Mixin.create({

        _normalizeTypeKey: function(key) {
            return Ember['default'].String.camelize(key);
        },

        dummyModelFor: function (key) {
            return {
                typeKey: this._normalizeTypeKey(key),
                store: this
            };
        },

        findFields: function (typeName) {
            var type = this.dummyModelFor(typeName);
            return this.fetchFields(type);
        },

        fetchFields: function (type) {
            var store = this,
                adapter = store.getDynamicAdapter(type.typeKey),
                promise = adapter.findFields(store, type),
                serializer = ApplicationSerializer['default'].create();

            return new Ember['default'].RSVP.Promise(function (resolve, reject) {
                resolve(
                    promise.then(function (adapterPayload) {
                        var extractedPayload = serializer.extract(store, type, adapterPayload, null, 'findFields');
                        return Ember['default'].A(extractedPayload);
                    })
                );
            });
        },

        getDynamicAdapter: function (typeName) {
            var adapterName = this._normalizeTypeKey(typeName),
                adapter = this.container.lookup('adapter:' + adapterName) || this.createDynamicAdapter(adapterName);

            return adapter;
        },

        createDynamicAdapter: function (adapterName) {
            var adapter = ApplicationAdapter['default'].extend();
            this.adapterRegistry(adapterName, adapter);
            return this.container.lookup('adapter:' + adapterName);
        },

        getDynamicModel: function (typeName, baseModel) {
            var modelName = this._normalizeTypeKey(typeName),
                model = this.container.lookup('model:' + modelName) || this.createDynamicModel(modelName, baseModel);

            return new Ember['default'].RSVP.Promise(function (resolve, reject) {
                resolve(model);
            });
        },

        createDynamicModel: function (typeName, baseModel) {
            var store = this,
                modelName = this._normalizeTypeKey(typeName),
                fieldsPayload = this.findFields(modelName);
            return new Ember['default'].RSVP.Promise(function (resolve, reject) {
                resolve(
                    fieldsPayload.then(function (fields) {
                        var model = baseModel || DS['default'].Model.extend(),
                            modelData = store._buildDynamicModelData(fields, Ember['default'].get(model, 'fields'), modelName);
                        model = model.extend(modelData);
                        model.reopenClass({
                            _fields: fields
                        });

                        store.modelRegistry(modelName, model);

                        return model;
                    })
                );
            });
        },

        _buildDynamicModelData: function (fields, modelFields, modelName) {
            var store = this,
                modelData = {},
                _modelFieldNames = [];

            modelFields.forEach(function (f, k) {
                _modelFieldNames.push(k);
            });

            fields.forEach(function (fieldData) {
                if (_modelFieldNames.indexOf(fieldData.fieldName) > -1) {
                    return;
                }
                modelData[fieldData.fieldName] = store.buildModelField(fieldData, modelName);
            });

            return modelData;
        },


        mapFieldTypeToAttrType: function (fieldType) {
            var attrType;
            switch (fieldType) {
                case 'string':
                case 'url':
                    attrType = 'string';
                    break;
                case 'number':
                case 'integer':
                    attrType = 'number';
                    break;
                case 'boolean':
                    attrType = 'booleanNull';
                    break;
                case 'date':
                case 'datetime':
                    attrType = 'string';
                    break;
                case 'json':
                    attrType = 'jsonString';
                    break;
                default:
                    break;
            }

            return attrType;
        },

        buildModelField: function (fieldData, modelName) {
            var fieldType = fieldData.type;

            if (fieldType === 'choice') {
                return this.buildModelBelongsToField(fieldData, modelName);
            }

            return DS['default'].attr(this.mapFieldTypeToAttrType(fieldType));
        },

        buildModelBelongsToField: function (fieldData, modelName) {
            var store = this,
                choices,
                payload = {},
                rawChoices = fieldData.choices || [],
                choiceModelName = modelName + 'Choice' + Ember['default'].String.capitalize(fieldData.fieldName),
                choiceModel = this.container.lookup('model:' + choiceModelName),
                serializer = ApplicationSerializer['default'].create();

            if (!choiceModel) {
                choiceModel = ModelFieldChoiceModel['default'].extend();
                store.modelRegistry(choiceModelName, choiceModel);
            }

            choices = Ember['default'].$.map(rawChoices, function (data, idx) {
                data.id = data.value;
                return data;
            });

            payload[choiceModelName] = choices;
            serializer.pushPayload(this, payload);

            return DS['default'].belongsTo(choiceModelName);

        }
    });

});
define('morgana/models/bulk-upload-general', ['exports', 'ember', 'ember-data'], function (exports, Ember, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        contentProject: DS['default'].belongsTo('content-project', {defaultValue: 0}),
        tag: DS['default'].attr('string'),
        dataFile: DS['default'].attr('uploadFile', {
            defaultValue: Ember['default'].Object.create({
                name: '',
                size: 0,
                type: '',
                content: null
            })
        })
    });

});
define('morgana/models/bulk-upload', ['exports', 'ember', 'ember-data', 'morgana/models/bulk-upload-general'], function (exports, Ember, DS, BulkUploadGeneral) {

	'use strict';

	exports['default'] = BulkUploadGeneral['default'].extend({
	});

});
define('morgana/models/category', ['exports', 'ember-data'], function (exports, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        name: DS['default'].attr('string'),
        checked: DS['default'].attr('boolean')
    });

});
define('morgana/models/content-project-export', ['exports', 'ember-data', 'ember'], function (exports, DS, Ember) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        status: DS['default'].attr('string'),
        message: DS['default'].attr('string'),
        details: DS['default'].attr('string'),
        created: DS['default'].attr(),
        downloadUrl: DS['default'].attr('string'),
        name: DS['default'].attr('string'),
        contentProject: DS['default'].belongsTo('content-project', {async: true}),
        isDownloadable: Ember['default'].computed('status', function () {
            return this.get('status') === 'done';
        })
    });

});
define('morgana/models/content-project', ['exports', 'ember', 'ember-data'], function (exports, Ember, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        name: DS['default'].attr('string'),
        axcompany_name: DS['default'].attr('string'),
        engineConfiguration: DS['default'].belongsTo('engine-configuration', {async: true}), //ASYNC IMPORTANT TO GET A PROMISE!
        keywordDensity: DS['default'].attr('number', {defaultValue: 3}),
        keywordDeviation: DS['default'].attr('number', {defaultValue: 33}),
        maxLength: DS['default'].attr('number', {defaultValue: 0}),
        things: DS['default'].hasMany('thing', {async: true}),

        generatingZip: DS['default'].attr(),
        imagesZipFile: DS['default'].attr(),
        countThings: DS['default'].attr('number'),
        countGeneratedTextsErrors: DS['default'].attr(),
        countGeneratedTexts: DS['default'].attr(),

        countGeneratedTextsDisplay: Ember['default'].computed('countGeneratedTexts', function () {
            return parseInt(this.get('countGeneratedTexts'), 10) || 0;
        }),

        countGeneratedTextsErrorsDisplay: Ember['default'].computed('countGeneratedTextsErrors', function () {
            return parseInt(this.get('countGeneratedTextsErrors'), 10) || 0;
        }),

        hasThings: Ember['default'].computed('countThings', function () {
            return this.get('countThings') > 0;
        })
    });

});
define('morgana/models/content-request', ['exports', 'ember', 'ember-data'], function (exports, Ember, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        thingUuid: DS['default'].attr(),
        celeryTaskId: DS['default'].attr(),
        thingType: DS['default'].attr(),
        state: DS['default'].attr(),
        content: DS['default'].attr(),
        duration: DS['default'].attr('number'),
        durationDisplay: Ember['default'].computed('duration', function () {
            var duration = parseFloat(this.get('duration'));

            return isNaN(duration) ? null : (duration  / 1000).toFixed(3);
        }),

        isText: Ember['default'].computed(function () {
            return false;
        }),
        isImage: Ember['default'].computed(function () {
            return false;
        })
    });

});
define('morgana/models/credit-history', ['exports', 'ember-data'], function (exports, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        amount: DS['default'].attr(),
        operation: DS['default'].attr(),
        last: DS['default'].attr()
    });

});
define('morgana/models/engine-configuration-status', ['exports', 'ember-data'], function (exports, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        identifier: DS['default'].attr('string'),
        name: DS['default'].attr('string'),
        description: DS['default'].attr('string'),
        checked: DS['default'].attr('boolean'),
        infoObjects: DS['default'].attr('string'),
        infoNoObjects: DS['default'].attr('string')
    });

});
define('morgana/models/engine-configuration', ['exports', 'ember', 'ember-data'], function (exports, Ember, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        name: Ember['default'].computed('descriptiveName', function () {
            return this.get('descriptiveName');
        }),

        descriptiveName: DS['default'].attr('string'),

        thingType: DS['default'].attr('string'),
        engineType: DS['default'].attr('string'),

        demoData: DS['default'].attr('string'),
        demoContent: DS['default'].attr('string'),
        description: DS['default'].attr('string'),


        hasThing: DS['default'].attr(),
        hasEngine: DS['default'].attr(),

        status: DS['default'].belongsTo('engine-configuration-status', {async: true}),
        language: DS['default'].belongsTo('language', {async: true}),
        engineContentTypeCategory: DS['default'].belongsTo('engine-content-type-category', {async: true}),

        isText: Ember['default'].computed.equal('engineType', 'text'),
        isImage: Ember['default'].computed.equal('engineType', 'image')
    });

});
define('morgana/models/engine-configurations-contact', ['exports', 'ember-data'], function (exports, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        message: DS['default'].attr('string')
    });

});
define('morgana/models/engine-content-type-category', ['exports', 'ember-data'], function (exports, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        name: DS['default'].attr('string'),
        description: DS['default'].attr('string'),
        checked: DS['default'].attr('boolean')
    });

});
define('morgana/models/eventlog', ['exports', 'ember-data'], function (exports, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        action: DS['default'].attr('string'),
        message: DS['default'].attr('string'),
        created: DS['default'].attr()
    });

});
define('morgana/models/field-requirement-level-data', ['exports', 'ember-data', 'ember'], function (exports, DS, Ember) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        label: DS['default'].attr('string'),
        value: DS['default'].attr(),
        requirementLevel: DS['default'].attr('number'),

        displayValue: Ember['default'].computed('value', function () {
            return Handlebars.Utils.escapeExpression(this.get('value'));
        }),
        displayLabel: Ember['default'].computed('label', function () {
            return Ember['default'].String.capitalize(Handlebars.Utils.escapeExpression(this.get('label')));
        }),
        requirementLevelCssClassName: Ember['default'].computed('requirementLevel', function () {
            return 'ax-field-level-' + (this.get('requirementLevel') || 0);
        }),
        requirementLevelEmptyCssClassName: Ember['default'].computed('requirementLevel', 'value', function () {
            return 'ax-field-' + (this.get('value') ? 'not-' : '') + 'empty';
        })

    });

});
define('morgana/models/image-request', ['exports', 'ember', 'ember-data', 'morgana/models/content-request'], function (exports, Ember, DS, ContentRequest) {

    'use strict';

    exports['default'] = ContentRequest['default'].extend({
        generatedImageUrl: DS['default'].attr('string'),

        content: Ember['default'].computed('generatedImageUrl', function () {
            return this.get('generatedImageUrl');
        }),
        isImage: Ember['default'].computed(function () {
            return true;
        })
    });

});
define('morgana/models/invoice', ['exports', 'ember-data'], function (exports, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        axcompany: DS['default'].attr('string'),
        invoiceNumber: DS['default'].attr('string'),
        invoiceDate: DS['default'].attr(),
        informationalText: DS['default'].attr('string')
    });

});
define('morgana/models/language', ['exports', 'ember-data'], function (exports, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        identifier: DS['default'].attr('string'),
        name: DS['default'].attr('string'),
        checked: DS['default'].attr('boolean')
    });

});
define('morgana/models/model-field-choice', ['exports', 'ember-data'], function (exports, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        displayName: DS['default'].attr(),
        value: DS['default'].attr()
    });

});
define('morgana/models/requirement-level-status', ['exports', 'ember-data'], function (exports, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        'name': DS['default'].attr('string'),
        'statusName': DS['default'].attr('string'),
        'filled_field_message': DS['default'].attr('string'),
        'unfilled_field_message': DS['default'].attr('string'),
        'object_message': DS['default'].attr('string')
    });

});
define('morgana/models/tag', ['exports', 'ember-data'], function (exports, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        name: DS['default'].attr('string'),
        count: DS['default'].attr(),
        contentProject: DS['default'].belongsTo('content-project', {async: true})
    });

});
define('morgana/models/text-request', ['exports', 'ember', 'ember-data', 'morgana/models/content-request'], function (exports, Ember, DS, ContentRequest) {

    'use strict';

    exports['default'] = ContentRequest['default'].extend({
        generatedText: DS['default'].attr('string'),
        spellingErrorCount: DS['default'].attr(),
        languageErrors: DS['default'].attr('jsonStringParsed'),

        content: Ember['default'].computed('generatedText', function () {
            return this.get('generatedText');
        }),
        isText: Ember['default'].computed(function () {
            return true;
        }),
        languageErrorCount: Ember['default'].computed('languageErrors', function () {
            var languageErrors = this.get('languageErrors');
            return (languageErrors && languageErrors.length) ? languageErrors.length : null;
        }),
        contentLength: Ember['default'].computed('generatedText', function () {
            return this.get('generatedText').length;
        })
    });

});
define('morgana/models/thing', ['exports', 'ember', 'ember-data'], function (exports, Ember, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        uid: DS['default'].attr('string'),
        sku: DS['default'].attr('string'),
        uuid: DS['default'].attr('string'),
        name: DS['default'].attr('string'),
        tag: DS['default'].attr('string', {readOnly: true}),
        status: DS['default'].attr('string'),
        errorMsg: DS['default'].attr('string'),
        modified: DS['default'].attr(),
        contentProject: DS['default'].belongsTo('content-project', {async: true}),
        requirementLevelStatusText: DS['default'].attr('string', {readOnly: true}),
        mostImportantMissingRequirementLevel: DS['default'].attr('string', {readOnly: true}),
        contentGenerationStatusCssClass: DS['default'].attr('string', {readOnly: true}),
        contentGenerationStatusText: DS['default'].attr('string', {readOnly: true}),

        // textLength are currently available only from es in list views. For detail views get this info from text request
        textLengthInChars: DS['default'].attr('number', {readOnly: true}),
        textLengthInWords: DS['default'].attr('number', {readOnly: true}),

        mostImportantMissingRequirementLevelClassName: Ember['default'].computed('mostImportantMissingRequirementLevel', function () {
            return 'ax-field-level-' + this.get('mostImportantMissingRequirementLevel');
        }),

        uuidUrlFormat: Ember['default'].computed('uuid', function () {
            return this.get('uuid').replace(/\-/g, '');
        }),

        hasMissingData: Ember['default'].computed('mostImportantMissingRequirementLevel', function () {
            return parseInt(this.get('mostImportantMissingRequirementLevel'), 10) > 0;
        })
    });

});
define('morgana/models/user-check-list', ['exports', 'ember-data'], function (exports, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        show: DS['default'].attr('boolean'),
        hasProfile: DS['default'].attr('boolean'),
        hasContentProject: DS['default'].attr('boolean'),
        hasThing: DS['default'].attr('boolean'),
        hasGeneratedContent: DS['default'].attr('boolean')
    });

});
define('morgana/models/user', ['exports', 'ember', 'ember-data'], function (exports, Ember, DS) {

    'use strict';

    exports['default'] = DS['default'].Model.extend({
        firstName: DS['default'].attr('string'),
        lastName: DS['default'].attr('string'),
        username: DS['default'].attr('string'),
        email: DS['default'].attr('string'),
        authToken: DS['default'].attr(),
        apiUrl: DS['default'].attr(),
        axcompany: DS['default'].attr(),
        companyCredits: DS['default'].attr(),
        availableFeatures: DS['default'].attr(),

        fullName: Ember['default'].computed('firstName', 'lastName', function () {
            return this.get('firstName') + ' ' + this.get('lastName');
        })
    });

});
define('morgana/router', ['exports', 'ember', 'morgana/config/environment'], function (exports, Ember, config) {

    'use strict';

    var Router = Ember['default'].Router.extend({
        location: config['default'].locationType
    });

    Router.map(function () {
        this.resource('home', { path: '/' }, function () {
            this.resource('credits', { path: '/credits' }, function () {
                return;
            });
            this.resource('engine-configurations', function () {
                this.route('contact');
            });
            this.resource('engine-configuration', { path: '/engine-configurations/:engine-configuration_id' }, function () {
                this.route('content-project', { path: '/content-project' }, function () {
                    this.route('new');
                });
            });
            this.resource('content-projects', function () {
                return;
            });
            this.resource('content-project', { path: 'content-project/:content-project_id' }, function () {
                this.route('edit');
                this.route('delete');
                this.route('content-project-exports', function () {
                });
                this.route('bulk-upload', { path: '/bulk-upload' }, function () {
                    this.route('upload');
                });
                this.route('thing-type', { path: '/things'}, function () {

                    this.route('thing-new', { path: '/new' });
                    this.route('thing', { path: '/:thing_id' }, function () {
                        this.route('edit');
                        this.route('delete');
                    });
                });
            });
            this.resource('eventlog', function () {
                return;
            });
            this.resource('tags', { path: '/tags' }, function () {
                this.route('upload');
            });
            this.resource('download-exports', { path: '/download-exports' }, function () {
                return;
            });
            this.resource('profile', function () {
                this.route('edit-company');
                this.route('edit-user');
            });
        });


        this.route('login');
    });

    exports['default'] = Router;

});
define('morgana/routes/application', ['exports', 'ember', 'simple-auth/mixins/application-route-mixin', 'morgana/mixins/flash-messages-route', 'morgana/mixins/permissions'], function (exports, Ember, ApplicationRouteMixin, FlashMessagesRouteMixin, permissions) {

    'use strict';

    window.Raven = window.Raven || null;


    exports['default'] = Ember['default'].Route.extend(ApplicationRouteMixin['default'], FlashMessagesRouteMixin['default'], {


        currentUser: Ember['default'].computed.alias('session.currentUser')


    });

});
define('morgana/routes/content-project', ['exports', 'ember', 'morgana/mixins/permissions'], function (exports, Ember, permissions) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        model: function (params) {
            var self = this,
                cp;
            if (params['content-project_id']) {
                cp = this.store.find('ContentProject', params['content-project_id']);
                cp.then(function (contentProject) {
                    contentProject.get('engineConfiguration').then(function (engineConfiguration) {
                        self._initPermissions(contentProject, engineConfiguration);
                    });
                });
                return cp;
            }
        },

        _initPermissions: function (contentProject, engineConfiguration) {
            var currentUser = this.get('session.currentUser');

            currentUser.reload();

            permissions.Permissions.register(
                permissions.Permission.extend({
                    name: 'toggle',
                    engineConfiguration: engineConfiguration,
                    can: Ember['default'].computed('engineConfiguration.isText', function () {
                        return this.get('engineConfiguration').get('isText');
                    })
                }).create()
            );

            permissions.Permissions.register(
                permissions.Permission.extend({
                    name: 'addThing',
                    engineConfiguration: engineConfiguration,
                    can: Ember['default'].computed('engineConfiguration.hasThing', function () {
                        return this.get('engineConfiguration').get('hasThing');
                    })
                }).create()
            );

            permissions.Permissions.register(
                permissions.Permission.extend({
                    name: 'createContent',
                    engineConfiguration: engineConfiguration,
                    contentProject: contentProject,
                    can: Ember['default'].computed('engineConfiguration.hasEngine', 'contentProject.hasThings', function () {
                        return this.get('contentProject').get('hasThings') && this.get('engineConfiguration').get('hasEngine');
                    })
                }).create()
            );

            permissions.Permissions.register(
                permissions.Permission.extend({
                    name: 'payForContent',
                    currentUser: currentUser,
                    can: Ember['default'].computed('currentUser.companyCredits', function () {
                        return parseInt(this.get('currentUser').get('companyCredits'), 10) > 0;
                    })
                }).create()
            );


            permissions.Permissions.register(
                permissions.Permission.extend({
                    name: 'downloadContent',
                    engineConfiguration: engineConfiguration,
                    contentProject: contentProject,
                    can: Ember['default'].computed('engineConfiguration.hasEngine', 'contentProject.hasThings', function () {
                        return this.get('contentProject').get('hasThings') && this.get('engineConfiguration').get('hasEngine');
                    })
                }).create()
            );


            permissions.Permissions.register(
                permissions.Permission.extend({
                    name: 'downloadImagesAsZip',
                    engineConfiguration: engineConfiguration,
                    contentProject: contentProject,
                    can: Ember['default'].computed('engineConfiguration.hasEngine', 'contentProject.imagesZipFile', function () {
                        return this.get('contentProject').get('imagesZipFile') && this.get('engineConfiguration').get('isImage') && this.get('engineConfiguration').get('hasEngine');
                    })
                }).create()
            );

            permissions.Permissions.register(
                permissions.Permission.extend({
                    name: 'generateImagesAsZip',
                    engineConfiguration: engineConfiguration,
                    contentProject: contentProject,
                    can: Ember['default'].computed('engineConfiguration.isImage', 'engineConfiguration.hasEngine', 'contentProject.hasThings', function () {
                        return this.get('engineConfiguration').get('isImage') && this.get('engineConfiguration').get('hasEngine') && this.get('contentProject').get('hasThings');
                    })
                }).create()
            );

            permissions.Permissions.register(
                permissions.Permission.extend({
                    name: 'downloadObjects',
                    contentProject: contentProject,
                    can: Ember['default'].computed('contentProject.hasThings', function () {
                        return this.get('contentProject').get('hasThings');
                    })
                }).create()
            );
        }

    });

});
define('morgana/routes/content-project/bulk-upload', ['exports', 'ember'], function (exports, Ember) {

	'use strict';

	exports['default'] = Ember['default'].Route.extend({
	});

});
define('morgana/routes/content-project/bulk-upload/upload', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        model: function (params) {
            var bulkupload = this.store.createRecord('bulkUpload');
            bulkupload.set('contentProject', this.modelFor('content-project'));
            return bulkupload;
        }
    });

});
define('morgana/routes/content-project/content-project-exports', ['exports', 'ember'], function (exports, Ember) {

	'use strict';

	exports['default'] = Ember['default'].Route.extend({
	});

});
define('morgana/routes/content-project/content-project-exports/index', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        setupController: function (controller) {
            var self = this,
                promise = new Ember['default'].RSVP.Promise(function (resolve, reject) {
                    var contentProject = self.modelFor('content-project'),
                        contentProjectExportAdapter = self.store.getDynamicAdapter('contentProjectExport');

                    contentProjectExportAdapter.reopen({
                        pathForType: function (type) {
                            return 'content-project/' + contentProject.get('id') + '/contentprojectexport';
                        }
                    });
                    resolve(controller._loadPage(1));
                });

            promise.then(function (model) {
                controller.set('model', model);
            });
        }
    });

});
define('morgana/routes/content-project/delete', ['exports', 'ember'], function (exports, Ember) {

	'use strict';

	exports['default'] = Ember['default'].Route.extend({
	});

});
define('morgana/routes/content-project/edit', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        setupController: function (controller, params) {
            controller.set('model', this.modelFor('content-project'));
        }
    });

});
define('morgana/routes/content-project/index', ['exports', 'ember', 'morgana/mixins/permissions'], function (exports, Ember, permissions) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
         _getThingsModel: function () {
            var self = this,
                controller = this.controllerFor('things/index'),
                contentProject = this.modelFor('content-project'),
                thingAdapter = self.store.getDynamicAdapter('Thing');

            thingAdapter.reopen({
                pathForType: function (type) {
                    return 'content-project/' + contentProject.get('id') + '/thinglist/';
                }
            });
            return controller._loadPage(1);

        },


        model: function (params) {
            return this.modelFor('content-project');
        },


        setupController: function (controller, context) {
            var thingsController = this.controllerFor('things/index'),
                contentProject = this.modelFor('content-project');

            this._super(controller, context);
            thingsController.set('contentProject', contentProject);
            this._getThingsModel().then(function (things) {
                thingsController.set('model', things);
            });

            controller.set('_perms', permissions.Permissions);


        },

        renderTemplate: function () {
            var thingsController = this.controllerFor('things/index');

            this.render('content_project/index');
            this.render('things/_thing_list', {
                into: 'content_project/index',
                outlet: 'things',
                controller: thingsController
            });
        }
    });

});
define('morgana/routes/content-project/thing-type', ['exports', 'ember'], function (exports, Ember) {

	'use strict';

	exports['default'] = Ember['default'].Route.extend({
	});

});
define('morgana/routes/content-project/thing-type/thing-new', ['exports', 'ember', 'morgana/models/thing'], function (exports, Ember, ThingModel) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        viewName: 'foundation',
        model: function (params) {
            var self = this,
                contentProject = this.modelFor('content-project'),
                model;

            model = contentProject.get('engineConfiguration').then(function (engineConfiguration) {
                var thingType = engineConfiguration.get('thingType'),
                    thingAdapter = self.store.getDynamicAdapter(thingType);

                thingAdapter.reopen({
                    pathForType: function (type) {
                        return 'content-project/' + contentProject.get('id') + '/thing';
                    }
                });

                return self.store.getDynamicModel(thingType, ThingModel['default']).then(function () {
                    var thing = self.store.createRecord(thingType);
                    thing.set('contentProject', contentProject);
                    return thing;
                });

            });

            return model;
        }
    });

});
define('morgana/routes/content-project/thing-type/thing', ['exports', 'ember', 'morgana/models/thing'], function (exports, Ember, ThingModel) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({

        model: function (params) {
            var self = this,
                contentProject = this.modelFor('content-project'),
                model;

            model = new Ember['default'].RSVP.Promise(function (resolve, reject) {
                contentProject.get('engineConfiguration').then(function (engineConfiguration) {
                    var thingType = engineConfiguration.get('thingType'),
                        thingAdapter = self.store.getDynamicAdapter(thingType),
                        ret = {};
                    thingAdapter.reopen({
                        pathForType: function (type) {
                            return 'content-project/' + contentProject.get('id') + '/thing';
                        },
                        useUpdateFieldsForDynamicModels: false
                    });


                    ret = self.store.getDynamicModel(thingType, ThingModel['default']).then(function () {
                        return self.store.find(thingType, params.thing_id);
                    });

                    resolve(ret);
                });
    //
            });

            return model;
        }
    });

});
define('morgana/routes/content-project/thing-type/thing/delete', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        viewName: 'foundation'
    });

});
define('morgana/routes/content-project/thing-type/thing/edit', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        viewName: 'foundation'
    });

});
define('morgana/routes/content-project/thing-type/thing/index', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        viewName: 'foundation',

        setupController: function (controller, context) {
            var self = this,
                contentProject = this.modelFor('contentProject');
            controller.set('contentRequest', null);
            contentProject.get('engineConfiguration').then(function (engineConfiguration) {
                var engineType = engineConfiguration.get('engineType'),
                    thingType = engineConfiguration.get('thingType'),
                    contentRequestClass = Ember['default'].String.capitalize(engineType) + 'Request',
                    contentRequestAdapter = self.store.getDynamicAdapter(contentRequestClass);

                contentRequestAdapter.pathForType = function (type) {
                    return self.store.getDynamicAdapter(thingType).pathForType() + '/' + context.get('id') + '/content_request';
                };

                self.store.unloadAll(contentRequestClass); //important otherwise findAll returns previously loaded crs aswell
                self.store.find(contentRequestClass, 'fakeId').then(function (contentRequest) {
                    controller.set('contentRequest', contentRequest);
                }, function (e) {
                    return; //nothing here
                });
                controller.set('engineConfiguration', engineConfiguration);
                controller.set('contentProject', contentProject);
            });

            this._super(controller, context);
        }
    });

});
define('morgana/routes/content-projects', ['exports', 'ember'], function (exports, Ember) {

	'use strict';

	exports['default'] = Ember['default'].Route.extend({
	});

});
define('morgana/routes/credits/index', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        viewName: 'foundation',

        model: function () {
            return this.get('currentUser');
        },
        currentUser: Ember['default'].computed(function () {
            return this.controllerFor('application').get('currentUser');
        }),
        setupController: function (controller, context) {
            context.reload();
            this._super(controller, context);
            this.setupCreditHistoryController();
            this.setupInvoicesController();
        },

        setupCreditHistoryController: function () {
            var controller = this.controllerFor('credits.creditHistory'),
                promise = this.store.find('credit-history');

            promise.then(function (model) {
                controller.set('model', model);
            });
        },

        setupInvoicesController: function () {
            var controller = this.controllerFor('credits.invoices'),
                promise = this.store.find('invoice');

            promise.then(function (model) {
                controller.set('model', model);
            });
        },

        renderTemplate: function () {
            this.render('credits/index');
            this.renderCreditHistory('credits/index');
            this.renderInvoices('credits/index');
        },

        renderCreditHistory: function (containerTemplate) {
            var controller = this.controllerFor('credits.creditHistory');
            this.render('credits/-credit-history', {
                into: containerTemplate,
                outlet: 'credit_history',
                controller: controller
            });
        },

        renderInvoices: function (containerTemplate) {
            var controller = this.controllerFor('credits.invoices');
            this.render('credits/-invoices', {
                into: containerTemplate,
                outlet: 'invoices',
                controller: controller
            });
        }



    });

});
define('morgana/routes/download-exports', ['exports', 'ember'], function (exports, Ember) {

	'use strict';

	exports['default'] = Ember['default'].Route.extend({



	});

});
define('morgana/routes/download-exports/index', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        setupController: function (controller) {
            var self = this,
                promise = new Ember['default'].RSVP.Promise(function (resolve, reject) {
                    var contentProjectExportAdapter = self.store.getDynamicAdapter('contentProjectExport');

                    contentProjectExportAdapter.reopen({
                        pathForType: function (type) {
                            return 'download-exports/';
                        }
                    });
                    resolve(controller._loadPage(1));
                });

            promise.then(function (model) {
                controller.set('model', model);
            });
        }
    });

});
define('morgana/routes/engine-configuration', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        model: function (params) {
            return this.store.find('EngineConfiguration', params['engine-configuration_id']);
        }
    });

});
define('morgana/routes/engine-configuration/content-project', ['exports', 'ember'], function (exports, Ember) {

	'use strict';

	exports['default'] = Ember['default'].Route.extend({
	});

});
define('morgana/routes/engine-configuration/content-project/new', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        model: function (params) {
            var contentProject = this.store.createRecord('contentProject');
            contentProject.set('engineConfiguration', this.modelFor('engine-configuration'));
            return contentProject;
        }
    });

});
define('morgana/routes/engine-configuration/index', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        model: function () {
            return this.modelFor('engine-configuration');
        }
    });

});
define('morgana/routes/engine-configurations', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        model: function () {
            var self = this;
            return new Ember['default'].RSVP.Promise(function (resolve, reject) {
                self.store.find('EngineConfiguration').then(function (engineConfigurations) {
                    engineConfigurations.forEach(function (engineConfiguration) {
                        var filters = engineConfiguration.get('filters') || [];
                        engineConfiguration.reopen({
                            filters: filters
                        });
                    });
                    resolve(engineConfigurations);
                });

            });
        }
    });

});
define('morgana/routes/engine-configurations/contact', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        model: function (params) {
            return this.store.createRecord('EngineConfigurationsContact');
        }
    });

});
define('morgana/routes/engine-configurations/index', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        model: function() {
            return this.modelFor('engine-configurations');
        }
    });

});
define('morgana/routes/eventlog', ['exports', 'ember'], function (exports, Ember) {

	'use strict';

	exports['default'] = Ember['default'].Route.extend({
	});

});
define('morgana/routes/eventlog/index', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        setupController: function (controller) {
            var promise = new Ember['default'].RSVP.Promise(function (resolve, reject) {
                    resolve(controller._loadPage(1));
                });
            promise.then(function (model) {
                controller.set('model', model);
            });
        }
    });

});
define('morgana/routes/home', ['exports', 'ember', 'simple-auth/mixins/authenticated-route-mixin', 'morgana/mixins/permissions'], function (exports, Ember, AuthenticatedRouteMixin, permissions) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend(AuthenticatedRouteMixin['default'], {



        model: function () {
            return this._initCurrentUser();
        },

        _initCurrentUser: function () {
            var route = this,
                currentUser;

                currentUser =  new Ember['default'].RSVP.Promise(function (resolve, reject) {
                    route.store.find('user', route.get('session.currentUserId')).then(function (user) {
                        if (user) {
                            try {
                                Raven.setUserContext({
                                    username: user.get('username'),
                                    id: user.get('id')
                                });
                            } catch (e) {
                                console.log('Raven is not defined');
                            }
                            route.get('session').set('currentUser', user);
                            route._initPermissions(user);

                            resolve(user);

                        } else {
                            try {
                                Raven.captureMessage('No user found!');
                            } catch (e) {
                                console.log('Raven is not defined');
                            }
                            reject();
                        }
                    }, function (e) {
                        try {
                            Raven.captureMessage('Error loading user', e);
                        } catch (e2) {
                            console.log('Raven is not defined');
                        }

                        reject();
                    });
                });

            return currentUser;
        },

        _initPermissions: function (currentUser) {
            permissions.Permissions.register(
                permissions.Permission.extend({
                    name: 'showTagOverview',
                    currentUser: currentUser,
                    can: Ember['default'].computed('currentUser.availableFeatures.show_tag_overview', function () {
                        return this.get('currentUser.availableFeatures.show_tag_overview');
                    })
                }).create()
            );
            permissions.Permissions.register(
                permissions.Permission.extend({
                    name: 'multiContentProjectUploads',
                    currentUser: currentUser,
                    can: Ember['default'].computed('currentUser.availableFeatures.multi_content_project_uploads', function () {
                        return this.get('currentUser.availableFeatures.multi_content_project_uploads');
                    })
                }).create()
            );
            permissions.Permissions.register(
                permissions.Permission.extend({
                    name: 'showSkuInTagList',
                    currentUser: currentUser,
                    can: Ember['default'].computed('currentUser.availableFeatures.show_sku_in_tag_list', function () {
                        return this.get('currentUser.availableFeatures.show_sku_in_tag_list');
                    })
                }).create()
            );
        }



    });

});
define('morgana/routes/home/index', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        model: function () {
            return this.get('currentUser');
        },

        setupController: function (controller, context) {
            context.reload();
            this._super(controller, context);
            this.setupContentProjectsController();
            this.setupUserCheckListController();
        },

        currentUser: Ember['default'].computed(function () {
            return this.controllerFor('application').get('currentUser');
        }),

        setupContentProjectsController: function () {
            var controller = this.controllerFor('contentProjects.index'),
                promise = new Ember['default'].RSVP.Promise(function (resolve, reject) {
                    resolve(controller._loadPage(1));
                });
            promise.then(function (model) {
                controller.set('model', model);
            });
        },

        setupUserCheckListController: function () {
            var controller = this.controllerFor('userCheckList.index'),
                promise = this.store.find('userCheckList');

            promise.then(function (userCheckList) {
                controller.set('model', userCheckList.objectAt(0));
            });
        },

        renderTemplate: function () {
            this.render('home/index');
            this.renderUserCheckList('home/index');
            this.renderContentProjects('home/index');
        },

        renderContentProjects: function (containerTemplate) {
            var controller = this.controllerFor('content-projects.index');
            this.render('content-projects/-content-project-list', {
                into: containerTemplate,
                outlet: 'content_project_list',
                controller: controller
            });
        },

        renderUserCheckList: function (containerTemplate) {
            var controller = this.controllerFor('userCheckList.index');
            this.render('home/-user-check-list', {
                into: containerTemplate,
                outlet: 'user_check_list',
                controller: controller
            });
        }
    });

});
define('morgana/routes/login', ['exports', 'ember', 'simple-auth/mixins/unauthenticated-route-mixin'], function (exports, Ember, UnauthenticatedRouteMixin) {

	'use strict';

	exports['default'] = Ember['default'].Route.extend(UnauthenticatedRouteMixin['default'], {

	});

});
define('morgana/routes/profile', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({

        model: function () {
            var self = this,
                currentUser = this.get('session.currentUser');
            return new Ember['default'].RSVP.Promise(function (resolve, reject) {

                var axCompanyAdapter = self.store.getDynamicAdapter('axCompany'),
                    ret;

                axCompanyAdapter.reopen({
                    useUpdateFieldsForDynamicModels: currentUser.get('axcompany')
                });

                ret = self.store.getDynamicModel('axCompany').then(function () {
                    return self.store.fetch('axCompany', currentUser.get('axcompany'));
                });

                resolve(ret);
            });
        }

    });

});
define('morgana/routes/profile/edit-company', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({

        model: function (params) {
            var model = this.modelFor('profile');
            model.send('becomeDirty');
            model.rollback();
            return model;
        }
    });

});
define('morgana/routes/profile/edit-user', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({
        model: function () {
            return this.get('currentUser');
        },

        setupController: function (controller, context) {
            context.reload();
            this._super(controller, context);
        },

        currentUser: Ember['default'].computed(function () {
            return this.controllerFor('application').get('currentUser');
        })
    });

});
define('morgana/routes/profile/index', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({

        model: function (params) {
            var model = this.modelFor('profile');
            model.send('becomeDirty');
            model.rollback();
            return model;
        },


        setupController: function (controller, context) {
            this.get('session.currentUser').reload();
            this._super(controller, context);
        }
    });

});
define('morgana/routes/tags', ['exports', 'ember', 'morgana/mixins/permissions'], function (exports, Ember, permissions) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({

        model: function () {
            var self = this,
                controller = this.controllerFor('tags/index'),
                thingAdapter = self.store.getDynamicAdapter('Thing');

            thingAdapter.reopen({
                pathForType: function () {
                    return 'allthings/';
                }
            });


            return this.store.find('contentProject', {page_size: 10000}).then(function () {
                return controller._loadPage(1);
            });
        },

        beforeModel: function () {
            var route = this,
                currentUser = this.get('session.currentUser');
            currentUser.reload().then(function (currentUser) {
                route._initPermissions(currentUser);
            });
        },

        _initPermissions: function (currentUser) {

            permissions.Permissions.register(
                permissions.Permission.extend({
                    name: 'payForContent',
                    currentUser: currentUser,
                    can: Ember['default'].computed('currentUser.companyCredits', function () {
                        return parseInt(currentUser.get('companyCredits'), 10) > 0;
                    })
                }).create()
            );
        }
    });

});
define('morgana/routes/tags/index', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({


        model: function () {
            var route = this,
                promise = new Ember['default'].RSVP.Promise(function (resolve) {
                    return route.store.find('requirementLevelStatus').then(function () {
                        resolve(route.modelFor('tags'));
                    });

                });

            return promise;
        }


    });

});
define('morgana/routes/tags/upload', ['exports', 'ember', 'ember-data', 'morgana/mixins/permissions'], function (exports, Ember, DS, permissions) {

    'use strict';

    exports['default'] = Ember['default'].Route.extend({

        model: function () {
            var route = this,
                canMultiContentProjectUploads = permissions.Permissions.getPermission('multiContentProjectUploads').get('can'),

                bulkUpload = new Ember['default'].RSVP.Promise(function (resolve, reject) {
                    if (canMultiContentProjectUploads) {
                        resolve(route.store.find('contentProject', {page_size: 1, page: 1}).then(function (contentProjects) {
                            var bulkUploadGeneral = route.store.createRecord('bulkUploadGeneral'),
                                firstContentProject = contentProjects.objectAt(0);

                            bulkUploadGeneral.set('contentProject', firstContentProject);

                            return bulkUploadGeneral;
                        }));

                    } else {
                        resolve(route.store.createRecord('bulkUploadGeneral'));
                    }
                });


            return bulkUpload;
        },

        setupController: function (controller, context) {
            var route = this,
                canMultiContentProjectUploads = permissions.Permissions.getPermission('multiContentProjectUploads').get('can'),
                allContentProjects;

            this._super(controller, context);

            if (!canMultiContentProjectUploads) {
                route.store.find('contentProject', {page_size: 10000, page: 1}).then(function (contentProjects) {
                    controller.set('allContentProjects', contentProjects);
                });

            }
        }
    });

});
define('morgana/serializers/application', ['exports', 'ember-data', 'ember', 'morgana/mixins/server-side-model-serializer'], function (exports, DS, Ember, ServerSideModelSerializerMixin) {

    'use strict';

    exports['default'] = DS['default'].RESTSerializer.extend(ServerSideModelSerializerMixin['default'], {
        keyForAttribute: function (attr) {
            return Ember['default'].String.underscore(attr);
        },
        keyForRelationship: function (attr) {
            return Ember['default'].String.underscore(attr);
        },
        serializeIntoHash: function (hash, type, record, options) {
            // No root element for restapi
            Ember['default'].$.extend(hash, this.serialize(record, options));
        },
        typeForRoot: function (key) {
            return Ember['default'].String.camelize(key);
        }
    });

});
define('morgana/serializers/content-request', ['exports', 'morgana/serializers/application'], function (exports, ApplicationSerializer) {

	'use strict';

	exports['default'] = ApplicationSerializer['default'].extend();

});
define('morgana/serializers/eventlog', ['exports', 'morgana/serializers/application'], function (exports, ApplicationSerializer) {

    'use strict';

    exports['default'] = ApplicationSerializer['default'].extend({
        typeForRoot: function () {
            return this._super('eventlog');
        }
    });

});
define('morgana/serializers/image-request', ['exports', 'morgana/serializers/content-request'], function (exports, ContentRequestSerializer) {

	'use strict';

	exports['default'] = ContentRequestSerializer['default'].extend({
	});

});
define('morgana/serializers/text-request', ['exports', 'morgana/serializers/content-request'], function (exports, ContentRequestSerializer) {

	'use strict';

	exports['default'] = ContentRequestSerializer['default'].extend({
	});

});
define('morgana/serializers/thing', ['exports', 'morgana/serializers/application'], function (exports, ApplicationSerializer) {

    'use strict';

    exports['default'] = ApplicationSerializer['default'].extend({
        typeForRoot: function () {
            return this._super('thing');
        },

        normalizeHash: {
            'thing': function (hash) {

                if (!hash.content_project && hash.content_project_pk) {
                    hash.content_project = hash.content_project_pk;
                }
                return hash;
            }
        },

        // because normalizeHash was called to late in super
        normalize: function(type, hash, prop) {
            if (this.normalizeHash && this.normalizeHash[prop]) {
                this.normalizeHash[prop](hash);
            }
            this.normalizeId(hash);
            this.normalizeAttributes(type, hash);
            this.normalizeRelationships(type, hash);
            this.normalizeUsingDeclaredMapping(type, hash);

            this.applyTransforms(type, hash);
            return hash;
        }

    });

});
define('morgana/serializers/user-check-list', ['exports', 'morgana/serializers/application'], function (exports, ApplicationSerializer) {

    'use strict';

    exports['default'] = ApplicationSerializer['default'].extend({

        extractSingle: function (store, type, payload, id, requestType) {
            var singlePayload = this.normalizeSingleObjectPayload(payload);
            return this._super(store, type, singlePayload, id, requestType);

        },
        extractArray: function (store, type, arrayPayload, id, requestType) {
            var singlePayload = this.normalizeSingleObjectPayload(arrayPayload, true);
            return this._super(store, type, singlePayload, id, requestType);
        },

        normalizeSingleObjectPayload: function (payload, isForArray) {
            var ret = {};
            payload.userCheckList.id = 'unique';

            if (isForArray) {
                ret.userCheckList = [payload.userCheckList];

            } else {
                ret = payload;
            }

            return ret;
        }
    });

});
define('morgana/store', ['exports', 'ember-data', 'morgana/mixins/server-side-model-store'], function (exports, DS, ServerSideModelStoreMixin) {

	'use strict';

	exports['default'] = DS['default'].Store.extend(ServerSideModelStoreMixin['default']);

});
define('morgana/templates/application', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, escapeExpression=this.escapeExpression, self=this, helperMissing=helpers.helperMissing, functionType="function", blockHelperMissing=helpers.blockHelperMissing;

  function program1(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n    ");
    stack1 = helpers['if'].call(depth0, "hasMessages", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(2, program2, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    }
  function program2(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n        <aside class=\"ember-flash-messages\" class=\"row\">\n        ");
    stack1 = helpers.each.call(depth0, "message", "in", "messages", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(3, program3, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n        </aside>\n    ");
    return buffer;
    }
  function program3(depth0,data) {
    
    var buffer = '';
    data.buffer.push("\n            <div class=\"columns\">\n          <div ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":alert-box message.messageType")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n              ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "child-view-or-string", {hash:{
      'contentBinding': ("message.text")
    },hashTypes:{'contentBinding': "STRING"},hashContexts:{'contentBinding': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n            <a href='#' class='dismiss' ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "dismissFlashMessage", "message", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0,depth0],types:["STRING","ID"],data:data})));
    data.buffer.push(">x</a>\n          </div>\n          </div>\n        ");
    return buffer;
    }

    data.buffer.push(escapeExpression((helper = helpers.render || (depth0 && depth0.render),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "navigation", options) : helperMissing.call(depth0, "render", "navigation", options))));
    data.buffer.push("\n\n");
    options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(1, program1, data),contexts:[],types:[],data:data}
    if (helper = helpers['flash-messages']) { stack1 = helper.call(depth0, options); }
    else { helper = (depth0 && depth0['flash-messages']); stack1 = typeof helper === functionType ? helper.call(depth0, options) : helper; }
    if (!helpers['flash-messages']) { stack1 = blockHelperMissing.call(depth0, 'flash-messages', {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(1, program1, data),contexts:[],types:[],data:data}); }
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n<main class=\"full-width\">\n    <section class=\"row\">\n        <div class=\"small-12 large-12 columns\">\n        ");
    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n            </div>\n    </section>\n</main>\n");
    return buffer;
    
  });

});
define('morgana/templates/components/button-with-loader', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, escapeExpression=this.escapeExpression;


    data.buffer.push("<a ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': ("displayAsButton:button displayAsButton:expand isLoading:loading isAlert:alert")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(" ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "showLoading", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(">");
    stack1 = helpers._triageMustache.call(depth0, "buttonText", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</a>\n");
    return buffer;
    
  });

});
define('morgana/templates/content-project', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1;


    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/content-project/-form-fields', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression;


    data.buffer.push("<section class=\"large-8 small-12 columns\">\n    <fieldset>\n\n        <div class=\"holder\" id=\"div_id_name\">\n            <label class=\"required\" for=\"id_name\">Name</label>\n            ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'value': ("name"),
      'id': ("id_name"),
      'class': ("textinput"),
      'required': (true),
      'autofocus': ("")
    },hashTypes:{'value': "ID",'id': "STRING",'class': "STRING",'required': "BOOLEAN",'autofocus': "STRING"},hashContexts:{'value': depth0,'id': depth0,'class': depth0,'required': depth0,'autofocus': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("\n            <small class=\"error\">This field is required.</small>\n        </div>\n    </fieldset>\n    <fieldset>\n        <legend>Advanced Configuration</legend>\n        <dl data-accordion=\"\" class=\"accordion\">\n            <dd class=\"accordion-navigation\">\n\n                <a href=\"#content-project-advanced-configuration\">\n                    <div class=\"accordion-navigation-head\">\n                        <div class=\"accordion-navigation-head-description\">\n                            For advanced configuration you can customize the generated content. Please be aware, that\n                            your choices made here will not directly correlate with the text output, since multiple\n                            factors play a role in content generation - and the stochastic functions apply to the bulk\n                            of content you generate, not necessarily to a single text. If you have no special needs, you\n                            should keep the default values.\n                        </div>\n                        <div class=\"accordion-navigation-head-icon\">\n                            <i class=\"right fi-plus\"></i>\n                        </div>\n                    </div>\n                </a>\n\n                <div class=\"content\" id=\"content-project-advanced-configuration\">\n\n                    <div class=\"holder\" id=\"div_id_keyword_density\">\n                        <div class=\"panel-info\">\n                            The keyword density regulates the usage of specific keywords in your text. We automatically\n                            select appropriate synonyms or matching terms. The default is set to 3.\n                        </div>\n                        <label class=\"required\" for=\"id_keyword_density\">\n                            Keyword density <span>(");
    stack1 = helpers._triageMustache.call(depth0, "keywordDensity", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(")</span>\n                        </label>\n                        ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'type': ("range"),
      'required': (true),
      'value': ("keywordDensity"),
      'id': ("id_keyword_density"),
      'min': ("1"),
      'max': ("10"),
      'step': ("0.1"),
      'pattern': ("number")
    },hashTypes:{'type': "STRING",'required': "BOOLEAN",'value': "ID",'id': "STRING",'min': "STRING",'max': "STRING",'step': "STRING",'pattern': "STRING"},hashContexts:{'type': depth0,'required': depth0,'value': depth0,'id': depth0,'min': depth0,'max': depth0,'step': depth0,'pattern': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("\n\n                        <small class=\"error\">This field requires a number &gt;= 0.</small>\n                    </div>\n                    <div class=\"holder\" id=\"div_id_keyword_deviation\">\n                        <div class=\"panel-info\">\n                            The keyword deviation index regulates the spread of the keyword density. The default is set\n                            to 33%, which will result of +/- 33% keyword density over the bulk content.\n                        </div>\n                        <label class=\"required\" for=\"id_keyword_deviation\">\n                            Keyword deviation <span>(");
    stack1 = helpers._triageMustache.call(depth0, "keywordDeviation", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(")</span>\n                        </label>\n                        ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'type': ("range"),
      'required': (true),
      'value': ("keywordDeviation"),
      'id': ("id_keyword_deviation"),
      'min': ("1"),
      'max': ("50"),
      'step': ("0.1"),
      'pattern': ("number")
    },hashTypes:{'type': "STRING",'required': "BOOLEAN",'value': "ID",'id': "STRING",'min': "STRING",'max': "STRING",'step': "STRING",'pattern': "STRING"},hashContexts:{'type': depth0,'required': depth0,'value': depth0,'id': depth0,'min': depth0,'max': depth0,'step': depth0,'pattern': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("\n                        <small class=\"error\">This field requires a number &gt;= 0.</small>\n                    </div>\n                    <div class=\"holder\" id=\"div_id_max_length\">\n                        <div class=\"panel-info\">\n                            Every Training Type has an intrinsic length, which depends on the available data and the\n                            programming of the training. If you need shorter text, you can limit the length of the text.\n                            Default is 0, which results in automatic.\n                        </div>\n                        <label for=\"id_max_length\">\n                            Max length <span>(");
    stack1 = helpers._triageMustache.call(depth0, "maxLength", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(")</span>\n                        </label>\n                        ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'type': ("range"),
      'required': (true),
      'value': ("maxLength"),
      'id': ("id_max_length"),
      'min': ("0"),
      'max': ("2500"),
      'step': ("1"),
      'pattern': ("^[0-9]*$")
    },hashTypes:{'type': "STRING",'required': "BOOLEAN",'value': "ID",'id': "STRING",'min': "STRING",'max': "STRING",'step': "STRING",'pattern': "STRING"},hashContexts:{'type': depth0,'required': depth0,'value': depth0,'id': depth0,'min': depth0,'max': depth0,'step': depth0,'pattern': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("\n                        <small class=\"error\">Only numbers &gt;= 0 are allowed.</small>\n                    </div>\n                </div>\n            </dd>\n        </dl>\n\n    </fieldset>\n\n</section>\n");
    return buffer;
    
  });

});
define('morgana/templates/content-project/bulk-upload', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1;


    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/content-project/bulk-upload/upload', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing;


    data.buffer.push("<section id=\"content_project_wizard\">\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Bulk Upload File\n                <small>");
    stack1 = helpers._triageMustache.call(depth0, "contentProject.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</small>\n\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n        <form ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "upload", {hash:{
      'on': ("submit")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(" data-abide>\n\n            <section class=\"large-8 small-12 columns\">\n                <fieldset>\n                    <div class=\"holder\" id=\"div_id_tag\">\n                        <label for=\"id_tag\">Tag</label>\n                        ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'value': ("tag"),
      'id': ("id_tag"),
      'class': ("textinput"),
      'placeholder': ("KWxx")
    },hashTypes:{'value': "ID",'id': "STRING",'class': "STRING",'placeholder': "STRING"},hashContexts:{'value': depth0,'id': depth0,'class': depth0,'placeholder': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("\n                    </div>\n                    <div class=\"holder\" id=\"div_id_data_file\">\n                        <label for=\"id_data_file\">File</label>\n                        ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "FileUploadField", {hash:{
      'uploadFile': ("dataFile")
    },hashTypes:{'uploadFile': "ID"},hashContexts:{'uploadFile': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n                    </div>\n                </fieldset>\n            </section>\n\n            <aside class=\"small-12 large-4 columns\">\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.back"),
      'buttonText': ("Back to Content Project Detail"),
      'action': ("back")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.upload"),
      'buttonText': ("Upload File"),
      'action': ("upload")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            </aside>\n        </form>\n    </div>\n</section>\n");
    return buffer;
    
  });

});
define('morgana/templates/content-project/content-project-exports', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1;


    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/content-project/content-project-exports/-content-project-export-list', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression, self=this;

  function program1(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n    ");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "things/_loading", options) : helperMissing.call(depth0, "partial", "things/_loading", options))));
    data.buffer.push("\n");
    return buffer;
    }

  function program3(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n\n");
    stack1 = helpers['if'].call(depth0, "hasItems", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(10, program10, data),fn:self.program(4, program4, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    }
  function program4(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n<table>\n    <thead>\n        <tr>\n            <th>Status</th>\n            <th>Created</th>\n            <th>Filename</th>\n            <th>Details</th>\n            <th></th>\n        </tr>\n    </thead>\n    <tbody>\n        ");
    stack1 = helpers.each.call(depth0, "export", "in", "model", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(5, program5, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n    </tbody>\n</table>\n");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "tableFooter", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data})));
    data.buffer.push("\n\n");
    return buffer;
    }
  function program5(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n        <tr>\n            <td>");
    stack1 = helpers._triageMustache.call(depth0, "export.status", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n            <td>");
    data.buffer.push(escapeExpression((helper = helpers.ago || (depth0 && depth0.ago),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "export.created", options) : helperMissing.call(depth0, "ago", "export.created", options))));
    data.buffer.push("</td>\n            <td>");
    stack1 = helpers._triageMustache.call(depth0, "export.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n            <td>");
    stack1 = helpers._triageMustache.call(depth0, "export.details", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n            <td>");
    stack1 = helpers['if'].call(depth0, "export.isDownloadable", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(8, program8, data),fn:self.program(6, program6, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n        </tr>\n        ");
    return buffer;
    }
  function program6(depth0,data) {
    
    var buffer = '';
    data.buffer.push("<a ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "downloadFile", "export", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0,depth0],types:["STRING","ID"],data:data})));
    data.buffer.push(">download</a>");
    return buffer;
    }

  function program8(depth0,data) {
    
    
    data.buffer.push("not ready (yet)");
    }

  function program10(depth0,data) {
    
    
    data.buffer.push("\n<div class=\"panel-info\">\n    There are no Exports.\n</div>\n");
    }

    stack1 = helpers['if'].call(depth0, "isLoading", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(3, program3, data),fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/content-project/content-project-exports/index', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', helper, options, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression;


    data.buffer.push("<section>\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Exports</h1>\n        </div>\n    </header>\n    <div class=\"row\">\n        <section class=\"large-8 small-12 columns\">\n            ");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "content_project/content-project-exports/-content-project-export-list", options) : helperMissing.call(depth0, "partial", "content_project/content-project-exports/-content-project-export-list", options))));
    data.buffer.push("\n        </section>\n        <aside class=\"small-12 large-4 columns\">\n\n        </aside>\n\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/content-project/delete', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression;


    data.buffer.push("<section id=\"content_project_wizard\">\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Delete Content Project ");
    stack1 = helpers._triageMustache.call(depth0, "name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("?\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n\n            <section class=\"large-8 small-12 columns\">\n                <div class=\"warn-delete-panel panel\">\n                     Are you sure that you want to delete this content project including all its objects and generated texts?\n                </div>\n            </section>\n\n            <aside class=\"small-12 large-4 columns\">\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.back"),
      'buttonText': ("Back to Content Project"),
      'action': ("back")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isAlert': (true),
      'isLoading': ("actionsLoadingStages.delete"),
      'buttonText': ("Yes, delete this Content Project!"),
      'action': ("delete")
    },hashTypes:{'isAlert': "BOOLEAN",'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isAlert': depth0,'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            </aside>\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/content-project/edit', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing;


    data.buffer.push("<section id=\"content_project_wizard\">\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Edit Content Project\n                <small>");
    stack1 = helpers._triageMustache.call(depth0, "name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</small>\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n        <form ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "edit", {hash:{
      'on': ("submit")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(" data-abide>\n\n            ");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "content-project/-form-fields", options) : helperMissing.call(depth0, "partial", "content-project/-form-fields", options))));
    data.buffer.push("\n\n            <aside class=\"small-12 large-4 columns\">\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.back"),
      'buttonText': ("Back to Content Project Detail"),
      'action': ("back")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.edit"),
      'buttonText': ("Save Content Project"),
      'action': ("edit")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            </aside>\n        </form>\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/content-project/index', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing, self=this;

  function program1(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                 <div data-dropdown=\"add_thing_drop\" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":dropdown :button :expand actionsLoadingStages.addThing:loading")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                    <span>\n                        Add Objects\n                    </span>\n                    <ul id=\"add_thing_drop\" class=\"f-dropdown content\" data-dropdown-content>\n                        <li>\n                            ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'displayAsButton': (false),
      'isLoading': ("actionsLoadingStages.addThing"),
      'buttonText': ("Add single object"),
      'action': ("createThing")
    },hashTypes:{'displayAsButton': "BOOLEAN",'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'displayAsButton': depth0,'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                        </li>\n                        <li>\n                            ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'displayAsButton': (false),
      'isLoading': ("actionsLoadingStages.addThing"),
      'buttonText': ("Import File"),
      'action': ("uploadFile")
    },hashTypes:{'displayAsButton': "BOOLEAN",'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'displayAsButton': depth0,'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                        </li>\n\n                    </ul>\n                 </div>\n\n            ");
    return buffer;
    }

  function program3(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n                ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.program(6, program6, data),fn:self.program(4, program4, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "payForContent", options) : helperMissing.call(depth0, "can-do", "payForContent", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n            ");
    return buffer;
    }
  function program4(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                    <div data-dropdown=\"generate_content_drop\" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":dropdown :button :expand actionsLoadingStages.generateContent:loading")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                        <span>\n                            Generate content\n                        </span>\n                        <ul id=\"generate_content_drop\" class=\"f-dropdown content\" data-dropdown-content>\n                            <li>\n                                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'displayAsButton': (false),
      'isLoading': ("actionsLoadingStages.generateContent"),
      'buttonText': ("Generate all missing content"),
      'action': ("generateContent")
    },hashTypes:{'displayAsButton': "BOOLEAN",'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'displayAsButton': depth0,'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                            </li>\n                            <li>\n                                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'displayAsButton': (false),
      'isLoading': ("actionsLoadingStages.generateContent"),
      'buttonText': ("(Re-)generate all content"),
      'action': ("forceGenerateContent")
    },hashTypes:{'displayAsButton': "BOOLEAN",'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'displayAsButton': depth0,'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                            </li>\n\n                        </ul>\n                    </div>\n\n\n                ");
    return buffer;
    }

  function program6(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                    <div>\n                        ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.buyCredits"),
      'buttonText': ("Buy credits to generate content"),
      'action': ("buyCredits")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                    </div>\n\n                ");
    return buffer;
    }

  function program8(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                 <div data-dropdown=\"download_content_drop\" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":dropdown :button :expand actionsLoadingStages.downloadContent:loading")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                    <span>\n                        Download content as Excel\n                    </span>\n                    <ul id=\"download_content_drop\" class=\"f-dropdown content\" data-dropdown-content>\n                        <li>\n                            ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'displayAsButton': (false),
      'isLoading': ("actionsLoadingStages.downloadContent"),
      'buttonText': ("Download texts as XLSX"),
      'action': ("downloadContent")
    },hashTypes:{'displayAsButton': "BOOLEAN",'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'displayAsButton': depth0,'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                        </li>\n                        <li>\n                            ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'displayAsButton': (false),
      'isLoading': ("actionsLoadingStages.downloadContent"),
      'buttonText': ("Download example XLSX"),
      'action': ("downloadExample")
    },hashTypes:{'displayAsButton': "BOOLEAN",'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'displayAsButton': depth0,'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                        </li>\n\n                    </ul>\n                 </div>\n\n            ");
    return buffer;
    }

  function program10(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                <div>\n                    ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.downloadImages"),
      'buttonText': ("Download images as zip"),
      'action': ("downloadImages")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                </div>\n            ");
    return buffer;
    }

  function program12(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n                ");
    stack1 = helpers['if'].call(depth0, "generatingZip", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(15, program15, data),fn:self.program(13, program13, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n            ");
    return buffer;
    }
  function program13(depth0,data) {
    
    
    data.buffer.push("\n                    <div>\n                        <a class=\"button expand disabled\" >\n                            Generating images zip\n                        </a>\n                    </div>\n                ");
    }

  function program15(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                    <div>\n                        ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.createImageZip"),
      'buttonText': ("(Re-)Generate images zip"),
      'action': ("createImageZip")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                    </div>\n                ");
    return buffer;
    }

    data.buffer.push("<section>\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>\n                Content Project&nbsp;\n                <small>");
    stack1 = helpers._triageMustache.call(depth0, "name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</small>\n            </h1>\n        </div>\n        <div class=\"small-12 columns\">\n        </div>\n    </header>\n    <div class=\"row\">\n        <section class=\"large-8 small-12 columns\">\n            <section>\n                ");
    data.buffer.push(escapeExpression((helper = helpers.outlet || (depth0 && depth0.outlet),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "things", options) : helperMissing.call(depth0, "outlet", "things", options))));
    data.buffer.push("\n            </section>\n        </section>\n        <aside class=\"small-12 large-4 columns\">\n            ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.back"),
      'buttonText': ("Back to Content Projects Overview"),
      'action': ("back")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n\n            ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "addThing", options) : helperMissing.call(depth0, "can-do", "addThing", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n\n            ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(3, program3, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "createContent", options) : helperMissing.call(depth0, "can-do", "createContent", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n\n            ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(8, program8, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "downloadContent", options) : helperMissing.call(depth0, "can-do", "downloadContent", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n\n            ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(10, program10, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "downloadImagesAsZip", options) : helperMissing.call(depth0, "can-do", "downloadImagesAsZip", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n\n            ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(12, program12, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "generateImagesAsZip", options) : helperMissing.call(depth0, "can-do", "generateImagesAsZip", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n            <div data-dropdown=\"edit_content_project_drop\"  ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":dropdown :button :expand actionsLoadingStages.edit:loading")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                <span>\n                    Edit this Content Project\n                </span>\n                <ul id=\"edit_content_project_drop\" class=\"f-dropdown content\" data-dropdown-content>\n                    <li>\n                        ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'displayAsButton': (false),
      'isLoading': ("actionsLoadingStages.edit"),
      'buttonText': ("Edit this Content Project"),
      'action': ("edit")
    },hashTypes:{'displayAsButton': "BOOLEAN",'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'displayAsButton': depth0,'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                    </li>\n                    <li>\n                        ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'displayAsButton': (false),
      'isLoading': ("actionsLoadingStages.edit"),
      'buttonText': ("Delete this Content Project"),
      'action': ("delete")
    },hashTypes:{'displayAsButton': "BOOLEAN",'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'displayAsButton': depth0,'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                    </li>\n\n                </ul>\n            </div>\n\n            <div>\n                <div class=\"panel callout radius\">\n                    <h5>\n                        Properties\n                    </h5>\n\n                    <ul class=\"detail-list\">\n                        <li>\n                            <span class=\"\">");
    stack1 = helpers._triageMustache.call(depth0, "countThings", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" Objects</span>\n                        </li>\n                        <li>\n                            <span class=\"\">");
    stack1 = helpers._triageMustache.call(depth0, "countGeneratedTextsDisplay", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" Texts </span>\n                        </li>\n                        <li>\n                            <span class=\"\">");
    stack1 = helpers._triageMustache.call(depth0, "countGeneratedTextsErrorsDisplay", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" Errors </span>\n                        </li>\n                        <li>\n                            <span class=\"\">Keyword Density: ");
    stack1 = helpers._triageMustache.call(depth0, "keywordDensity", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" </span>\n                        </li>\n                        <li>\n                            <span class=\"\">Keyword Deviation: ");
    stack1 = helpers._triageMustache.call(depth0, "keywordDeviation", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" </span>\n                        </li>\n                        <li>\n                            <span class=\"\">Max Length: ");
    stack1 = helpers._triageMustache.call(depth0, "maxLength", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</span>\n                        </li>\n                        <li>\n                            <span class=\"\">Training Type: ");
    stack1 = helpers._triageMustache.call(depth0, "engineConfiguration.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</span>\n                        </li>\n                        <li>\n                            <span class=\"\">Category: ");
    stack1 = helpers._triageMustache.call(depth0, "engineConfiguration.engineContentTypeCategory.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</span>\n                        </li>\n                        <li>\n                            <span class=\"\">Language: ");
    stack1 = helpers._triageMustache.call(depth0, "engineConfiguration.language.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</span>\n                        </li>\n                        <li>\n                            <span class=\"\">Status: ");
    stack1 = helpers._triageMustache.call(depth0, "engineConfiguration.status.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</span>\n                        </li>\n                    </ul>\n                </div>\n            </div>\n        </aside>\n    </div>\n</section>\n");
    return buffer;
    
  });

});
define('morgana/templates/content-project/thing-type', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1;


    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/content-project/thing-type/thing-new', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing;


    data.buffer.push("<section id=\"content_project_wizard\">\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Create New Object\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n\n        <form ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "create", {hash:{
      'on': ("submit")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(" data-abide>\n            <section class=\"large-8 small-12 columns\">\n                ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "serverSideModelFormFields", {hash:{
      'modelBinding': ("model"),
      'mainFieldBinding': ("mainFields"),
      'optionalFieldsBinding': ("optionalFields")
    },hashTypes:{'modelBinding': "STRING",'mainFieldBinding': "STRING",'optionalFieldsBinding': "STRING"},hashContexts:{'modelBinding': depth0,'mainFieldBinding': depth0,'optionalFieldsBinding': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n            </section>\n\n            <aside class=\"small-12 large-4 columns\">\n                <div data-ax-fixed-container>\n                    ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.back"),
      'buttonText': ("Back to Content Project Detail"),
      'action': ("back")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                    ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.create"),
      'buttonText': ("Create Object"),
      'action': ("create")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                </div>\n            </aside>\n        </form>\n\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/content-project/thing-type/thing', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1;


    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/content-project/thing-type/thing/-server-side-model-form-field-container', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing;


    data.buffer.push("<div class=\"holder\">\n    <label>\n        <label ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': ("field.required:required")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">");
    data.buffer.push(escapeExpression((helper = helpers['capitalize-string'] || (depth0 && depth0['capitalize-string']),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "field.label", options) : helperMissing.call(depth0, "capitalize-string", "field.label", options))));
    data.buffer.push("</label>\n        <div class=\"row collapse\">\n            <div class=\"small-11 columns\">\n                ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "serverSideModelFormField", {hash:{
      'fieldBinding': ("field"),
      'modelBinding': ("model")
    },hashTypes:{'fieldBinding': "STRING",'modelBinding': "STRING"},hashContexts:{'fieldBinding': depth0,'modelBinding': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n            </div>\n            <div class=\"small-1 columns\">\n                ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "serverSideModelFormFieldIndicator", {hash:{
      'fieldBinding': ("field"),
      'modelBinding': ("model")
    },hashTypes:{'fieldBinding': "STRING",'modelBinding': "STRING"},hashContexts:{'fieldBinding': depth0,'modelBinding': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n            </div>\n        </div>\n    </label>\n</div>");
    return buffer;
    
  });

});
define('morgana/templates/content-project/thing-type/thing/-server-side-model-form-fields', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, escapeExpression=this.escapeExpression, self=this;

  function program1(depth0,data) {
    
    var buffer = '';
    data.buffer.push("\n        ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "serverSideModelFormFieldContainer", {hash:{
      'fieldBinding': ("field"),
      'modelBinding': ("model")
    },hashTypes:{'fieldBinding': "STRING",'modelBinding': "STRING"},hashContexts:{'fieldBinding': depth0,'modelBinding': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n    ");
    return buffer;
    }

  function program3(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n    <fieldset>\n        <legend>Optional Fields</legend>\n        <dl data-accordion=\"\" class=\"accordion\">\n            <dd class=\"accordion-navigation\">\n\n                <a href=\"#optional-fields\">\n                    <div class=\"accordion-navigation-head\">\n                        <div class=\"accordion-navigation-head-description\">\n                            You can provide additional information about the object. This can improve the quality of your content even further.\n                        </div>\n                        <div class=\"accordion-navigation-head-icon\">\n                            <i class=\"right fi-plus\"></i>\n                        </div>\n                    </div>\n                </a>\n\n                <div class=\"content\" id=\"optional-fields\">\n                    ");
    stack1 = helpers.each.call(depth0, "field", "in", "optionalFields", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(4, program4, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                </div>\n            </dd>\n        </dl>\n    </fieldset>\n\n");
    return buffer;
    }
  function program4(depth0,data) {
    
    var buffer = '';
    data.buffer.push("\n                        ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "serverSideModelFormFieldContainer", {hash:{
      'fieldBinding': ("field"),
      'modelBinding': ("model")
    },hashTypes:{'fieldBinding': "STRING",'modelBinding': "STRING"},hashContexts:{'fieldBinding': depth0,'modelBinding': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n                    ");
    return buffer;
    }

    data.buffer.push("\n<fieldset>\n    ");
    stack1 = helpers.each.call(depth0, "field", "in", "mainFields", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(1, program1, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n</fieldset>\n");
    stack1 = helpers['if'].call(depth0, "optionalFields", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(3, program3, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/content-project/thing-type/thing/delete', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression;


    data.buffer.push("<section id=\"content_project_wizard\">\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Delete Objectt ");
    stack1 = helpers._triageMustache.call(depth0, "name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("?\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n\n            <section class=\"large-8 small-12 columns\">\n                <div class=\"warn-delete-panel panel\">\n                     Are you sure that you want to delete this object and generated texts?\n                </div>\n            </section>\n\n            <aside class=\"small-12 large-4 columns\">\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.back"),
      'buttonText': ("Back to Object Detail"),
      'action': ("back")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isAlert': (true),
      'isLoading': ("actionsLoadingStages.delete"),
      'buttonText': ("Yes, delete this Object!"),
      'action': ("delete")
    },hashTypes:{'isAlert': "BOOLEAN",'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isAlert': depth0,'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            </aside>\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/content-project/thing-type/thing/edit', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing;


    data.buffer.push("<section>\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Edit Object\n                <small>");
    stack1 = helpers._triageMustache.call(depth0, "uid", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" ");
    stack1 = helpers._triageMustache.call(depth0, "name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</small>\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n\n        <form ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "edit", {hash:{
      'on': ("submit")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(" data-abide>\n            <section class=\"large-8 small-12 columns\">\n                ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "serverSideModelFormFields", {hash:{
      'modelBinding': ("model"),
      'mainFieldBinding': ("mainFields"),
      'optionalFieldsBinding': ("optionalFields")
    },hashTypes:{'modelBinding': "STRING",'mainFieldBinding': "STRING",'optionalFieldsBinding': "STRING"},hashContexts:{'modelBinding': depth0,'mainFieldBinding': depth0,'optionalFieldsBinding': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n            </section>\n\n            <aside class=\"small-12 large-4 columns\">\n                <div data-ax-fixed-container>\n                    ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.back"),
      'buttonText': ("Back to Object Detail"),
      'action': ("back")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                    ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.edit"),
      'buttonText': ("Save Object"),
      'action': ("edit")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                </div>\n            </aside>\n        </form>\n\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/content-project/thing-type/thing/index', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression, self=this;

  function program1(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n            <div class=\"panel-alert panel text-center panel\">\n                ");
    stack1 = helpers._triageMustache.call(depth0, "errorMsg", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n            </div>\n            ");
    return buffer;
    }

  function program3(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n                <section>\n\n                    <div id=\"content-output\" class=\"notranslate\">\n\n                        ");
    stack1 = helpers['if'].call(depth0, "contentRequest.isText", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(6, program6, data),fn:self.program(4, program4, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                    </div>\n                </section>\n            ");
    return buffer;
    }
  function program4(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                            ");
    data.buffer.push(escapeExpression((helper = helpers['text-with-errors'] || (depth0 && depth0['text-with-errors']),options={hash:{
      'errors': ("contentRequest.languageErrors")
    },hashTypes:{'errors': "ID"},hashContexts:{'errors': depth0},contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "contentRequest.content", options) : helperMissing.call(depth0, "text-with-errors", "contentRequest.content", options))));
    data.buffer.push("\n                        ");
    return buffer;
    }

  function program6(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n                            ");
    stack1 = helpers['if'].call(depth0, "contentRequest.isImage", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(7, program7, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                        ");
    return buffer;
    }
  function program7(depth0,data) {
    
    var buffer = '';
    data.buffer.push("\n                                <div class=\"text-center\">\n                                    <a target=\"_blank\" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'href': ("contentRequest.content")
    },hashTypes:{'href': "STRING"},hashContexts:{'href': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                                        <img ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'src': ("contentRequest.content")
    },hashTypes:{'src': "STRING"},hashContexts:{'src': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                                    </a>\n                                </div>\n                            ");
    return buffer;
    }

  function program9(depth0,data) {
    
    
    data.buffer.push("\n                        <li class=\"tab-title\"><a href=\"#metrics\">Analytics</a></li>\n                    ");
    }

  function program11(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n                        <div class=\"content\" id=\"metrics\">\n                            <table>\n                                <tr>\n                                    <th class=\"text-right\">Generation time in seconds:</th>\n                                    <td>");
    stack1 = helpers._triageMustache.call(depth0, "contentRequest.durationDisplay", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n                                </tr>\n                                ");
    stack1 = helpers['if'].call(depth0, "contentRequest.isText", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(12, program12, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n                            </table>\n                        </div>\n                    ");
    return buffer;
    }
  function program12(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n                                    <tr>\n                                        <th class=\"text-right\">Spelling errors:</th>\n                                        <td>");
    stack1 = helpers._triageMustache.call(depth0, "contentRequest.spellingErrorCount", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n                                    </tr>\n                                    <tr>\n                                        <th class=\"text-right\">Spelling/grammar errors:</th>\n                                        <td>");
    stack1 = helpers._triageMustache.call(depth0, "contentRequest.languageErrorCount", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n                                    </tr>\n                                ");
    return buffer;
    }

  function program14(depth0,data) {
    
    
    data.buffer.push("To Content Project");
    }

  function program16(depth0,data) {
    
    
    data.buffer.push("To Import List");
    }

  function program18(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n                ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.program(24, program24, data),fn:self.program(19, program19, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "payForContent", options) : helperMissing.call(depth0, "can-do", "payForContent", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n            ");
    return buffer;
    }
  function program19(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n\n                    <div>\n                        ");
    stack1 = helpers['if'].call(depth0, "model.isContentGenerationAvailable", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(22, program22, data),fn:self.program(20, program20, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                    </div>\n\n                ");
    return buffer;
    }
  function program20(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                            ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.generateContent"),
      'buttonText': ("Generate content"),
      'action': ("generateContent")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                        ");
    return buffer;
    }

  function program22(depth0,data) {
    
    
    data.buffer.push("\n                            <button\n                                data-tooltip\n                                aria-haspopup=\"true\"\n                                role=\"tooltip\"\n                                class=\"low expand disabled has-tip\"\n                                title=\"The requirements for content generation are unmet. Please check your data and improve data quality.\">\n                                Content generation unavailable</button>\n                        ");
    }

  function program24(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                    <div>\n                        ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.buyCredits"),
      'buttonText': ("Buy Credits to generate content"),
      'action': ("buyCredits")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                    </div>\n                ");
    return buffer;
    }

    data.buffer.push("<section id=\"content_project_wizard\">\n\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Object Detail&nbsp;\n                <small class=\"notranslate\">");
    stack1 = helpers._triageMustache.call(depth0, "model.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</small>\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n        <section class=\"large-8 small-12 columns\">\n            <div ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': ("infoPanelStatusCssClass :text-center :panel")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                ");
    stack1 = helpers._triageMustache.call(depth0, "contentGenerationStatusText", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n            </div>\n            ");
    stack1 = helpers['if'].call(depth0, "errorMsg", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n            ");
    stack1 = helpers['if'].call(depth0, "contentRequest.content", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(3, program3, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n            <section>\n\n                <ul class=\"tabs\" data-tab>\n                    <li class=\"tab-title active\"><a href=\"#properties-simple\">Properties</a></li>\n                    <li class=\"tab-title\"><a href=\"#properties-complete\">All Data</a></li>\n                    ");
    stack1 = helpers['if'].call(depth0, "contentRequest", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(9, program9, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                </ul>\n                <div class=\"tabs-content\">\n                    <div class=\"content active\" id=\"properties-simple\">\n                        ");
    data.buffer.push(escapeExpression((helper = helpers['field-detail'] || (depth0 && depth0['field-detail']),options={hash:{
      'fields': ("mainFields"),
      'model': ("model")
    },hashTypes:{'fields': "ID",'model': "ID"},hashContexts:{'fields': depth0,'model': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "field-detail", options))));
    data.buffer.push("\n                    </div>\n                    <div class=\"content\" id=\"properties-complete\">\n                        ");
    data.buffer.push(escapeExpression((helper = helpers['field-detail'] || (depth0 && depth0['field-detail']),options={hash:{
      'fields': ("fields"),
      'model': ("model")
    },hashTypes:{'fields': "ID",'model': "ID"},hashContexts:{'fields': depth0,'model': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "field-detail", options))));
    data.buffer.push("\n                    </div>\n                    ");
    stack1 = helpers['if'].call(depth0, "contentRequest", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(11, program11, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                </div>\n            </section>\n        </section>\n        <aside class=\"small-12 large-4 columns\">\n            ");
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{
      'classNames': ("button expand low")
    },hashTypes:{'classNames': "STRING"},hashContexts:{'classNames': depth0},inverse:self.noop,fn:self.program(14, program14, data),contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "content-project", options) : helperMissing.call(depth0, "link-to", "content-project", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n            ");
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{
      'classNames': ("button expand low")
    },hashTypes:{'classNames': "STRING"},hashContexts:{'classNames': depth0},inverse:self.noop,fn:self.program(16, program16, data),contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "tags", options) : helperMissing.call(depth0, "link-to", "tags", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n            ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(18, program18, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "createContent", options) : helperMissing.call(depth0, "can-do", "createContent", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n            <div data-dropdown=\"edit_thing_drop\"  ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":dropdown :button :expand actionsLoadingStages.edit:loading")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                <span>\n                    Edit this Object\n                </span>\n                <ul id=\"edit_thing_drop\" class=\"f-dropdown content\" data-dropdown-content>\n                    <li>\n                        ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'displayAsButton': (false),
      'isLoading': ("actionsLoadingStages.edit"),
      'buttonText': ("Edit this Object"),
      'action': ("edit")
    },hashTypes:{'displayAsButton': "BOOLEAN",'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'displayAsButton': depth0,'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                    </li>\n                    <li>\n                        ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'displayAsButton': (false),
      'isLoading': ("actionsLoadingStages.edit"),
      'buttonText': ("Delete this Object"),
      'action': ("delete")
    },hashTypes:{'displayAsButton': "BOOLEAN",'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'displayAsButton': depth0,'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                    </li>\n\n                </ul>\n            </div>\n\n            <div>\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.reportJiraIssue"),
      'buttonText': ("Report an issue with this text"),
      'action': ("reportJiraIssue")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            </div>\n\n\n\n        </aside>\n\n\n    </div>\n</section>\n");
    return buffer;
    
  });

});
define('morgana/templates/content-projects', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1;


    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/content-projects/-content-project-list', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression, self=this;

  function program1(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n    ");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "things/-loading", options) : helperMissing.call(depth0, "partial", "things/-loading", options))));
    data.buffer.push("\n");
    return buffer;
    }

  function program3(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n\n");
    stack1 = helpers['if'].call(depth0, "hasItems", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(7, program7, data),fn:self.program(4, program4, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    }
  function program4(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n    <table>\n        <thead>\n            <tr>\n                <th>Content Project</th>\n                <th>Training Type</th>\n                <th>Status</th>\n                <th>Owner</th>\n                <th># Processed</th>\n                <th># of Errors</th>\n            </tr>\n        </thead>\n        <tbody>\n        ");
    stack1 = helpers.each.call(depth0, "contentProject", "in", "model", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(5, program5, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n        <tbody>\n    </table>\n    ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "tableFooter", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data})));
    data.buffer.push("\n");
    return buffer;
    }
  function program5(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n            <tr ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "contentProjectDetail", "contentProject", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0,depth0],types:["STRING","ID"],data:data})));
    data.buffer.push(" class=\"clickable\">\n                <td>");
    stack1 = helpers._triageMustache.call(depth0, "contentProject.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n                <td>");
    stack1 = helpers._triageMustache.call(depth0, "contentProject.engineConfiguration.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n                <td>");
    stack1 = helpers._triageMustache.call(depth0, "contentProject.engineConfiguration.status.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n                <td>");
    stack1 = helpers._triageMustache.call(depth0, "contentProject.axcompany_name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n                <td>");
    stack1 = helpers._triageMustache.call(depth0, "contentProject.countGeneratedTexts", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("/");
    stack1 = helpers._triageMustache.call(depth0, "contentProject.countThings", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n                <td>");
    stack1 = helpers._triageMustache.call(depth0, "contentProject.countGeneratedTextsErrors", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n            </tr>\n        ");
    return buffer;
    }

  function program7(depth0,data) {
    
    
    data.buffer.push("\n\n");
    }

    stack1 = helpers['if'].call(depth0, "isLoading", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(3, program3, data),fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/content-projects/index', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', helper, options, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression;


    data.buffer.push("<section>\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Content Projects\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n        <section class=\"large-8 small-12 columns\">\n           ");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "content-projects/_content-project-list", options) : helperMissing.call(depth0, "partial", "content-projects/_content-project-list", options))));
    data.buffer.push("\n        </section>\n        <aside class=\"small-12 large-4 columns\">\n            <a ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "createContentProject", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n                class=\"button expand\">\n                Create Content Project\n            </a>\n        </aside>\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/credits/-credit-history', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression, self=this;

  function program1(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                ");
    data.buffer.push(escapeExpression((helper = helpers.render || (depth0 && depth0.render),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0,depth0],types:["STRING","ID"],data:data},helper ? helper.call(depth0, "credits/credit-history-element", "creditHistoryElement", options) : helperMissing.call(depth0, "render", "credits/credit-history-element", "creditHistoryElement", options))));
    data.buffer.push("\n            ");
    return buffer;
    }

    data.buffer.push("<div>\n    <table>\n        <tbody>\n            ");
    stack1 = helpers.each.call(depth0, "creditHistoryElement", "in", "model", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(1, program1, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n        </tbody>\n    </table>\n</div>");
    return buffer;
    
  });

});
define('morgana/templates/credits/-invoices', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression, self=this;

  function program1(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n            <tr>\n                <td>\n                    <div class=\"row ax-invoice\">\n                        <div class=\"small-3 columns ax-invoice-name\">\n                            ");
    stack1 = helpers._triageMustache.call(depth0, "invoice.invoiceNumber", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                        </div>\n                        <div class=\"small-2 columns text-right ax-invoice-date\">\n                            ");
    stack1 = helpers['if'].call(depth0, "invoice.invoiceDate", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(2, program2, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                        </div>\n                        <div class=\"small-5 columns text-left ax-invoice-name\">\n                            ");
    stack1 = helpers._triageMustache.call(depth0, "invoice.informationalText", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                        </div>\n                        <div class=\"small-2 columns text-right\">\n                            <a class=\"button small\" ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "downloadInvoice", "invoice", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0,depth0],types:["ID","ID"],data:data})));
    data.buffer.push("><i class=\"fi-download\"></i> Download now</a>\n                        </div>\n                    </div>\n                </td>\n            </tr>\n        ");
    return buffer;
    }
  function program2(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                                <label><i class=\"fi-calendar\"></i>\n                                    ");
    data.buffer.push(escapeExpression((helper = helpers.moment || (depth0 && depth0.moment),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0,depth0],types:["ID","STRING"],data:data},helper ? helper.call(depth0, "invoice.invoiceDate", "YYYY-MM-DD", options) : helperMissing.call(depth0, "moment", "invoice.invoiceDate", "YYYY-MM-DD", options))));
    data.buffer.push("\n                                </label>\n                            ");
    return buffer;
    }

  function program4(depth0,data) {
    
    
    data.buffer.push("\n            <tr>\n                <td>\n                    Your Invoices are listed here for further reference. Please allow approximately 3 business days\n                    until the invoice is shown here.\n                </td>\n            </tr>\n        ");
    }

    data.buffer.push("<div>\n    <table>\n        <tbody>\n        ");
    stack1 = helpers.each.call(depth0, "invoice", "in", "model", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(4, program4, data),fn:self.program(1, program1, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n        </tbody>\n    </table>\n</div>");
    return buffer;
    
  });

});
define('morgana/templates/credits/credit-history-element', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression, self=this;

  function program1(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n            ");
    stack1 = helpers._triageMustache.call(depth0, "model.amount", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" credits added (most recently ");
    data.buffer.push(escapeExpression((helper = helpers.ago || (depth0 && depth0.ago),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "model.last", options) : helperMissing.call(depth0, "ago", "model.last", options))));
    data.buffer.push(" ago)\n        ");
    return buffer;
    }

  function program3(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n            ");
    stack1 = helpers._triageMustache.call(depth0, "model.amount", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" credits deducted (most recently ");
    data.buffer.push(escapeExpression((helper = helpers.ago || (depth0 && depth0.ago),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "model.last", options) : helperMissing.call(depth0, "ago", "model.last", options))));
    data.buffer.push(" ago)\n        ");
    return buffer;
    }

    data.buffer.push("<tr>\n    <td>\n        ");
    stack1 = helpers['if'].call(depth0, "isAdd", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(3, program3, data),fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n    </td>\n</tr>");
    return buffer;
    
  });

});
define('morgana/templates/credits/index', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression;


    data.buffer.push("<section>\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Credit\n                <small>Overview</small>\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n\n        <section class=\"large-8 small-12 columns\">\n            <div class=\"user-credits\">\n                You have <label>");
    stack1 = helpers._triageMustache.call(depth0, "model.companyCredits", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</label> credits left\n            </div>\n            <ul class=\"tabs\" data-tab>\n                <li class=\"tab-title active\"><a href=\"#credit-tab-1\">History</a></dd>\n                <li class=\"tab-title\"><a href=\"#credit-tab-2\">Invoices</a></dd>\n            </ul>\n            <div class=\"tabs-content\">\n                <div class=\"content active\" id=\"credit-tab-1\">\n                    ");
    data.buffer.push(escapeExpression((helper = helpers.outlet || (depth0 && depth0.outlet),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "credit_history", options) : helperMissing.call(depth0, "outlet", "credit_history", options))));
    data.buffer.push("\n                </div>\n                <div class=\"content\" id=\"credit-tab-2\">\n                    ");
    data.buffer.push(escapeExpression((helper = helpers.outlet || (depth0 && depth0.outlet),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "invoices", options) : helperMissing.call(depth0, "outlet", "invoices", options))));
    data.buffer.push("\n                </div>\n            </div>\n        </section>\n        <aside class=\"small-12 large-4 columns\">\n\n            <h4>Buy More Credits!</h4>\n\n            <div class=\"text-right\">\n                <a class=\"button expand\"\n                   href=\"https://sites.fastspring.com/aexea/instant/small1000\"\n                        >\n                    1,000 Credits / 250 €\n                </a>\n            </div>\n            <div>\n                <a class=\"button expand\"\n                   href=\"https://sites.fastspring.com/aexea/instant/medium5500\"\n                        >\n                    5,500 Credits / 1000 €\n                </a>\n            </div>\n            <div>\n                <a class=\"button expand\"\n                   href=\"https://sites.fastspring.com/aexea/instant/large30000\"\n                        >\n                    30,000 Credits / 5000 €\n                </a>\n            </div>\n            <div class=\"panel callout radius\">\n                Please Note: Payments will be handled via our payment provider FastSpring.\n            </div>\n\n        </aside>\n    </div>\n</section>\n");
    return buffer;
    
  });

});
define('morgana/templates/download-exports', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1;


    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/download-exports/index', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing, self=this;

  function program1(depth0,data) {
    
    var buffer = '';
    data.buffer.push("\n                <button ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "toTags", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(" class=\"button expand low\">To Import List</button>\n            ");
    return buffer;
    }

    data.buffer.push("<section>\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Exports</h1>\n        </div>\n    </header>\n    <div class=\"row\">\n        <section class=\"large-8 small-12 columns\">\n            ");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "content_project/content-project-exports/-content-project-export-list", options) : helperMissing.call(depth0, "partial", "content_project/content-project-exports/-content-project-export-list", options))));
    data.buffer.push("\n        </section>\n        <aside class=\"small-12 large-4 columns\">\n            <button ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "toContentProjects", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(" class=\"button expand low\">To Content Projects Overview</button>\n            ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "showTagOverview", options) : helperMissing.call(depth0, "can-do", "showTagOverview", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n        </aside>\n\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/engine-configuration', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1;


    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/engine-configuration/content-project', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1;


    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/engine-configuration/content-project/new', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing;


    data.buffer.push("<section id=\"content_project_wizard\">\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Create Content Project\n                <small>for ");
    stack1 = helpers._triageMustache.call(depth0, "engineConfiguration.descriptiveName", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</small>\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n        <form ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "create", {hash:{
      'on': ("submit")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(" data-abide>\n\n            ");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "content-project/-form-fields", options) : helperMissing.call(depth0, "partial", "content-project/-form-fields", options))));
    data.buffer.push("\n\n            <aside class=\"small-12 large-4 columns\">\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.back"),
      'buttonText': ("Back to Training Type"),
      'action': ("back")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.edit"),
      'buttonText': ("Create Content Project"),
      'action': ("create")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            </aside>\n        </form>\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/engine-configuration/index', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, escapeExpression=this.escapeExpression, self=this;

  function program1(depth0,data) {
    
    var buffer = '';
    data.buffer.push("\n                    ");
    data.buffer.push(escapeExpression(helpers._triageMustache.call(depth0, "demoData", {hash:{
      'unescaped': ("true")
    },hashTypes:{'unescaped': "STRING"},hashContexts:{'unescaped': depth0},contexts:[depth0],types:["ID"],data:data})));
    data.buffer.push("\n                ");
    return buffer;
    }

  function program3(depth0,data) {
    
    
    data.buffer.push("\n                    There's no Demo data yet.\n                ");
    }

  function program5(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n                    ");
    stack1 = helpers['if'].call(depth0, "isText", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(6, program6, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                ");
    return buffer;
    }
  function program6(depth0,data) {
    
    var buffer = '';
    data.buffer.push("\n                        ");
    data.buffer.push(escapeExpression(helpers._triageMustache.call(depth0, "demoContent", {hash:{
      'unescaped': ("true")
    },hashTypes:{'unescaped': "STRING"},hashContexts:{'unescaped': depth0},contexts:[depth0],types:["ID"],data:data})));
    data.buffer.push("\n                    ");
    return buffer;
    }

  function program8(depth0,data) {
    
    
    data.buffer.push("\n                    There's no Demo content yet.\n                ");
    }

    data.buffer.push("<section id=\"content_project_wizard\">\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Training Type\n                <small>for ");
    stack1 = helpers._triageMustache.call(depth0, "descriptiveName", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</small>\n            </h1>\n            <div class=\"engine-configuration-description\">\n                ");
    data.buffer.push(escapeExpression(helpers._triageMustache.call(depth0, "description", {hash:{
      'unescaped': ("true")
    },hashTypes:{'unescaped': "STRING"},hashContexts:{'unescaped': depth0},contexts:[depth0],types:["ID"],data:data})));
    data.buffer.push("\n            </div>\n        </div>\n    </header>\n    <div class=\"row\">\n        <section class=\"large-8 small-12 columns\">\n            <section>\n                <h3>Demo Data</h3>\n                <div class=\"demo\">\n                ");
    stack1 = helpers['if'].call(depth0, "demoData", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(3, program3, data),fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                </div>\n            </section>\n            <section>\n                <h3>Demo Content</h3>\n                <div class=\"demo\">\n                ");
    stack1 = helpers['if'].call(depth0, "demoContent", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(8, program8, data),fn:self.program(5, program5, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                </div>\n            </section>\n        </section>\n        <aside class=\"small-12 large-4 columns\">\n            <button ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "back", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n                class=\"button expand low\">\n                Back to Training Types\n            </button>\n            <button ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "createContentProject", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n                class=\"button expand\">\n                Create Content Project\n            </button>\n            <section>\n                <h3>Details</h3>\n                <dl>\n                    <dt>Category</dt>\n                    <dd><label>");
    stack1 = helpers._triageMustache.call(depth0, "engineContentTypeCategory.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</label><span>");
    stack1 = helpers._triageMustache.call(depth0, "engineContentTypeCategory.description", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</span></dd>\n                    <dt>Language</dt>\n                    <dd>");
    stack1 = helpers._triageMustache.call(depth0, "language.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</dd>\n                    <dt>Status</dt>\n                    <dd><label>");
    stack1 = helpers._triageMustache.call(depth0, "status.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</label><span>");
    stack1 = helpers._triageMustache.call(depth0, "status.description", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</span></dd>\n                </dl>\n            </section>\n        </aside>\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/engine-configurations', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1;


    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/engine-configurations/contact', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing;


    data.buffer.push("<section id=\"content_project_wizard\">\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Contact us\n                <small>for your content needs</small>\n            </h1>\n            <p>\n                We would be happy to provide content for you.\n            </p>\n            <p>\n                Please provide us with some info on your content needs, the medium/plattform you plan to use the content on, and what data you can provide.\n            </p>\n            <p>\n                We will contact you with details on how to proceed and with pricing information.\n            </p>\n        </div>\n    </header>\n    <div class=\"row\">\n        <form ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "create", {hash:{
      'on': ("submit")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(" data-abide>\n\n           <section class=\"large-8 small-12 columns\">\n                <fieldset>\n\n                    <div class=\"holder\" id=\"div_id_message\">\n                        <label class=\"required\" for=\"id_message\">Your message</label>\n                        ");
    data.buffer.push(escapeExpression((helper = helpers.textarea || (depth0 && depth0.textarea),options={hash:{
      'value': ("message"),
      'id': ("id_message"),
      'class': ("textinput"),
      'required': (true)
    },hashTypes:{'value': "ID",'id': "STRING",'class': "STRING",'required': "BOOLEAN"},hashContexts:{'value': depth0,'id': depth0,'class': depth0,'required': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "textarea", options))));
    data.buffer.push("\n                        <small class=\"error\">This field is required.</small>\n                    </div>\n\n                </fieldset>\n           </section>\n\n            <aside class=\"small-12 large-4 columns\">\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.back"),
      'buttonText': ("Back to Training Types"),
      'action': ("back")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.edit"),
      'buttonText': ("Send your message"),
      'action': ("create")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            </aside>\n        </form>\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/engine-configurations/index', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing, self=this;

  function program1(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n                    <li ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': ("status.checked:checked")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push("><label>");
    stack1 = helpers._triageMustache.call(depth0, "status.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'type': ("checkbox"),
      'checked': ("status.checked")
    },hashTypes:{'type': "STRING",'checked': "ID"},hashContexts:{'type': depth0,'checked': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("</label></li>\n                ");
    return buffer;
    }

  function program3(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n                    <li ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': ("language.checked:checked")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push("><label>");
    stack1 = helpers._triageMustache.call(depth0, "language.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'type': ("checkbox"),
      'checked': ("language.checked")
    },hashTypes:{'type': "STRING",'checked': "ID"},hashContexts:{'type': depth0,'checked': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("</label></li>\n                ");
    return buffer;
    }

  function program5(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n                    <li ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': ("category.checked:checked")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push("><label>");
    stack1 = helpers._triageMustache.call(depth0, "category.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'type': ("checkbox"),
      'checked': ("category.checked")
    },hashTypes:{'type': "STRING",'checked': "ID"},hashContexts:{'type': depth0,'checked': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("</label></li>\n                ");
    return buffer;
    }

  function program7(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n            <div class=\"row\">\n                <div class=\"columns\">\n                    <ul class=\"engine-configuration-list columns\">\n                        ");
    stack1 = helpers.each.call(depth0, "engineConfiguration", "in", "filteredContent", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(8, program8, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                        <li class=\"contact-us\">\n                            ");
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(11, program11, data),contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "engine-configurations.contact", options) : helperMissing.call(depth0, "link-to", "engine-configurations.contact", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                        </li>\n                    </ul>\n                </div>\n            </div>\n            ");
    return buffer;
    }
  function program8(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n                        <li ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': ("engineConfiguration.status.id")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                            ");
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(9, program9, data),contexts:[depth0,depth0],types:["STRING","ID"],data:data},helper ? helper.call(depth0, "engine-configuration", "engineConfiguration.id", options) : helperMissing.call(depth0, "link-to", "engine-configuration", "engineConfiguration.id", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                        </li>\n                        ");
    return buffer;
    }
  function program9(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n                                ");
    stack1 = helpers._triageMustache.call(depth0, "engineConfiguration.descriptiveName", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                            ");
    return buffer;
    }

  function program11(depth0,data) {
    
    
    data.buffer.push(" You couldn't find what you need? Please contact us!");
    }

  function program13(depth0,data) {
    
    
    data.buffer.push("\n            <div class=\"row\">\n                <div class=\"columns\">\n                    <p>No Training Type found for your search.</p>\n                </div>\n            </div>\n            ");
    }

    data.buffer.push("<section id=\"content_project_wizard\">\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Please select a Training Type for your new Content Project\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n        <section class=\"large-8 small-12 columns\">\n            <div class=\"row\">\n\n        <aside class=\"large-4 columns\">\n            <label class=\"ax-filter-box\">\n                ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'type': ("text"),
      'value': ("myFilter"),
      'placeholder': ("Filter"),
      'autofocus': ("")
    },hashTypes:{'type': "STRING",'value': "ID",'placeholder': "STRING",'autofocus': "STRING"},hashContexts:{'type': depth0,'value': depth0,'placeholder': depth0,'autofocus': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("\n                <i class=\"fi-magnifying-glass\"></i>\n            </label>\n            <h3>Status</h3>\n            <ul class=\"facette-list\">\n                ");
    stack1 = helpers.each.call(depth0, "status", "in", "allEngineConfigurationStatus", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(1, program1, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n            </ul>\n            <h3>Languages</h3>\n            <ul class=\"facette-list\">\n                ");
    stack1 = helpers.each.call(depth0, "language", "in", "allLanguages", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(3, program3, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n            </ul>\n            <h3>Categories</h3>\n            <ul class=\"facette-list\">\n                ");
    stack1 = helpers.each.call(depth0, "category", "in", "allEngineContentTypeCategories", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(5, program5, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n            </ul>\n        </aside>\n        <section class=\"large-8 columns\">\n            ");
    stack1 = helpers['if'].call(depth0, "filteredContent", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(13, program13, data),fn:self.program(7, program7, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n        </section>\n    </div>\n            </section>\n\n\n        <aside class=\"small-12 large-4 columns\">\n            <a ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "back", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n                class=\"button expand low\">\n                Back to Content Project Overview\n            </a>\n        </aside>\n\n    </div>\n\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/eventlog', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1;


    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/eventlog/-eventlog-list', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression, self=this;

  function program1(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n    ");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "things/-loading", options) : helperMissing.call(depth0, "partial", "things/-loading", options))));
    data.buffer.push("\n");
    return buffer;
    }

  function program3(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n\n");
    stack1 = helpers['if'].call(depth0, "hasItems", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(7, program7, data),fn:self.program(4, program4, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    }
  function program4(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n<table>\n  <thead>\n    <tr>\n      <th>Action</th>\n      <th>Message</th>\n      <th>Created</th>\n    </tr>\n  </thead>\n  <tbody>\n    ");
    stack1 = helpers.each.call(depth0, "event", "in", "model", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(5, program5, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n  </tbody>\n</table>\n    <div class=\"row\">\n      <div class=\"columns text-right\">\n        <ul class=\"pagination\">\n          <li>\n            <a ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "previous", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(">Previous</a>\n          </li>\n          <li>\n            ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "select", {hash:{
      'content': ("allPages"),
      'value': ("selectedPage")
    },hashTypes:{'content': "ID",'value': "ID"},hashContexts:{'content': depth0,'value': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n          </li>\n          <li>\n            <a ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "next", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(">Next</a>\n          </li>\n        </ul>\n      </div>\n    </div>\n\n    ");
    return buffer;
    }
  function program5(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n\n    <tr>\n      <td>");
    stack1 = helpers._triageMustache.call(depth0, "event.action", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n      <td>");
    stack1 = helpers._triageMustache.call(depth0, "event.message", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n      <td>");
    data.buffer.push(escapeExpression((helper = helpers.ago || (depth0 && depth0.ago),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "event.created", options) : helperMissing.call(depth0, "ago", "event.created", options))));
    data.buffer.push("</td>\n    </tr>\n    ");
    return buffer;
    }

  function program7(depth0,data) {
    
    
    data.buffer.push("\n    <div class=\"panel-info\">\n      There are no Events.\n    </div>\n    ");
    }

    stack1 = helpers['if'].call(depth0, "isLoading", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(3, program3, data),fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/eventlog/index', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', helper, options, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression;


    data.buffer.push("<section>\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>EventLog</h1>\n        </div>\n    </header>\n    <div class=\"row\">\n        <section class=\"large-8 small-12 columns\">\n            ");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "eventlog/-eventlog-list", options) : helperMissing.call(depth0, "partial", "eventlog/-eventlog-list", options))));
    data.buffer.push("\n        </section>\n        <aside class=\"small-12 large-4 columns\">\n\n        </aside>\n\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/home', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1;


    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/home/-user-check-list', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var stack1, escapeExpression=this.escapeExpression, self=this;

  function program1(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n    <div class=\"panel callout radius\">\n        <section class=\"row\">\n            <div class=\"small-12 columns\">\n                <p>\n                    <strong>We added some Demo Content to your account</strong> below and invite you to explore the\n                    features of myAx by\n                    generating some texts.\n                </p>\n                <h4>\n                    Things you should do next:\n                </h4>\n            </div>\n\n            <div class=\"small-12 large-6 columns\">\n                <ol id=\"checklist\">\n                    <li>\n                        Explore the Demo Content Projects\n                    </li>\n                    <li ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': ("hasProfile:complete")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                        ");
    stack1 = helpers['if'].call(depth0, "hasProfile", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(4, program4, data),fn:self.program(2, program2, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                    </li>\n                    <li ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': ("hasContentProject:complete")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                        ");
    stack1 = helpers['if'].call(depth0, "hasContentProject", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(8, program8, data),fn:self.program(6, program6, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                    </li>\n                    <li ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': ("hasThing:complete")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                        Add Objects to your Content Project\n                    </li>\n                    <li ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': ("hasGeneratedContent:complete")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                        Request your first Generated Content from AX\n                    </li>\n                </ol>\n\n            </div>\n            <div class=\"small-12 large-6 columns\">\n                <p>\n                    If you want to generate content for your own production systems, <a ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "addContentProject", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data})));
    data.buffer.push(">add a Content Project</a>.\n                </p>\n            </div>\n\n\n        </section>\n    </div>\n");
    return buffer;
    }
  function program2(depth0,data) {
    
    
    data.buffer.push("\n                            Complete your Profile\n                        ");
    }

  function program4(depth0,data) {
    
    var buffer = '';
    data.buffer.push("\n                            <a ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "editProfile", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data})));
    data.buffer.push(">Complete your Profile</a>\n                        ");
    return buffer;
    }

  function program6(depth0,data) {
    
    
    data.buffer.push("\n                            Add own Content Projects\n                        ");
    }

  function program8(depth0,data) {
    
    var buffer = '';
    data.buffer.push("\n                            <a ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "addContentProject", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data})));
    data.buffer.push(">Add own Content Projects</a>\n                        ");
    return buffer;
    }

    stack1 = helpers['if'].call(depth0, "show", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    else { data.buffer.push(''); }
    
  });

});
define('morgana/templates/home/_account_status', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, escapeExpression=this.escapeExpression;


    data.buffer.push("\n<div class=\"panel callout radius pricing-table\">\n                    <h5>\n                        Your Account Status\n                    </h5>\n                    <p class=\"price\">\n            <a ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "creditOverview", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(">\n\n                <span>");
    stack1 = helpers._triageMustache.call(depth0, "currentUser.companyCredits", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</span>\n                <small>credits left</small>\n            </a>\n        </p>\n    </div>");
    return buffer;
    
  });

});
define('morgana/templates/home/index', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression;


    data.buffer.push("<section>\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Hello ");
    stack1 = helpers._triageMustache.call(depth0, "model.firstName", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" ");
    stack1 = helpers._triageMustache.call(depth0, "model.lastName", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n        <section class=\"large-8 small-12 columns\">\n            ");
    data.buffer.push(escapeExpression((helper = helpers.outlet || (depth0 && depth0.outlet),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "user_check_list", options) : helperMissing.call(depth0, "outlet", "user_check_list", options))));
    data.buffer.push("\n            ");
    data.buffer.push(escapeExpression((helper = helpers.outlet || (depth0 && depth0.outlet),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "content_project_list", options) : helperMissing.call(depth0, "outlet", "content_project_list", options))));
    data.buffer.push("\n        </section>\n        <aside class=\"small-12 large-4 columns\">\n            <div>\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.addContentProject"),
      'buttonText': ("Add Content Project"),
      'action': ("addContentProject")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            </div>\n            ");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "home/_account_status", options) : helperMissing.call(depth0, "partial", "home/_account_status", options))));
    data.buffer.push("\n        </aside>\n    </div>\n</section>\n");
    return buffer;
    
  });

});
define('morgana/templates/loading', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    


    data.buffer.push("<section>\n   <div class=\"row\">\n       <div class=\"small-12 columns text-center\">\n            <img src=\"/assets/ax-template/svg/ax-loader.min.svg\" class=\"small-12 medium-4\" alt=\"\" />\n            <h2>Loading...</h2>\n       </div>\n   </div>\n</section>");
    
  });

});
define('morgana/templates/login', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression, self=this;

  function program1(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n            ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.invalidateSession"),
      'buttonText': ("Logout"),
      'action': ("invalidateSession")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            ");
    return buffer;
    }

  function program3(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n            ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.authenticateSession"),
      'buttonText': ("Login"),
      'action': ("authenticate")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            ");
    return buffer;
    }

    data.buffer.push("<section>\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Login\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n\n        <section class=\"large-8 small-12 columns\">\n            <form ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "authenticate", {hash:{
      'on': ("submit")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(" data-abide>\n                <div class=\"holder\">\n                    <label class=\"required\" for=\"id_email\">Email</label>\n                    ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'value': ("identification"),
      'id': ("id_email"),
      'class': ("textinput"),
      'required': (true),
      'autofocus': ("")
    },hashTypes:{'value': "ID",'id': "STRING",'class': "STRING",'required': "BOOLEAN",'autofocus': "STRING"},hashContexts:{'value': depth0,'id': depth0,'class': depth0,'required': depth0,'autofocus': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("\n                    <small class=\"error\">This field is required.</small>\n                </div>\n                <div class=\"holder\">\n                    <label class=\"required\" for=\"id_password\">Password</label>\n                    ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'value': ("password"),
      'id': ("id_password"),
      'class': ("password"),
      'type': ("password"),
      'required': (true)
    },hashTypes:{'value': "ID",'id': "STRING",'class': "STRING",'type': "STRING",'required': "BOOLEAN"},hashContexts:{'value': depth0,'id': depth0,'class': depth0,'type': depth0,'required': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("\n                    <small class=\"error\">This field is required.</small>\n                </div>\n            </form>\n        </section>\n        <aside class=\"small-12 large-4 columns\">\n            ");
    stack1 = helpers['if'].call(depth0, "session.isAuthenticated", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(3, program3, data),fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n        </aside>\n\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/navigation', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, self=this, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression;

  function program1(depth0,data) {
    
    
    data.buffer.push("<img alt=\"Logo\" src=\"/assets/ax-template/img/logo.png\">");
    }

  function program3(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n            <ul class=\"left\">\n                <li>\n                    ");
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(4, program4, data),contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "home", options) : helperMissing.call(depth0, "link-to", "home", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                </li>\n\n    ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(6, program6, data),contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "showTagOverview", options) : helperMissing.call(depth0, "can-do", "showTagOverview", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                <li>\n                    ");
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(13, program13, data),contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "profile", options) : helperMissing.call(depth0, "link-to", "profile", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                </li>\n\n                <li>\n                    ");
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(15, program15, data),contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "eventlog", options) : helperMissing.call(depth0, "link-to", "eventlog", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                </li>\n\n\n                <li class=\"\">\n                    ");
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(17, program17, data),contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "credits", options) : helperMissing.call(depth0, "link-to", "credits", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                </li>\n\n\n            </ul>\n\n\n            <!-- Right Nav Section -->\n            <ul class=\"right\">\n\n                <li class=\"has-dropdown not-click\">\n                    <a href=\"javascript:;\">");
    stack1 = helpers._triageMustache.call(depth0, "currentUser.email", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</a>\n\n                    <ul class=\"dropdown\">\n\n                        <li>\n\n                                <a ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "invalidateSession", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("><i class=\"step fi-lock size-16\"></i>Logout</a>\n\n                        </li>\n                    </ul>\n                </li>\n\n            </ul>\n");
    return buffer;
    }
  function program4(depth0,data) {
    
    
    data.buffer.push("\n                        <i class=\"step fi-home size-16\"></i> Home\n                    ");
    }

  function program6(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n                <li class=\"has-dropdown\">\n                    <a href=\"javascript:;\">Data Overview</a>\n                    <ul class=\"dropdown\">\n\n                        <li>\n                            ");
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(7, program7, data),contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "tags.upload", options) : helperMissing.call(depth0, "link-to", "tags.upload", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                        </li>\n\n                        <li>\n                            ");
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(9, program9, data),contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "tags", options) : helperMissing.call(depth0, "link-to", "tags", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                        </li>\n                        <li>\n                            ");
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(11, program11, data),contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "download-exports", options) : helperMissing.call(depth0, "link-to", "download-exports", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                        </li>\n                    </ul>\n                </li>\n    ");
    return buffer;
    }
  function program7(depth0,data) {
    
    
    data.buffer.push("\n                                Upload Data File\n                            ");
    }

  function program9(depth0,data) {
    
    
    data.buffer.push("\n                                List Objects\n                            ");
    }

  function program11(depth0,data) {
    
    
    data.buffer.push("\n                                Download Content\n                            ");
    }

  function program13(depth0,data) {
    
    
    data.buffer.push("\n                        Profile\n                    ");
    }

  function program15(depth0,data) {
    
    
    data.buffer.push("\n                        Eventlog\n                    ");
    }

  function program17(depth0,data) {
    
    
    data.buffer.push("\n                        Credits\n                    ");
    }

    data.buffer.push("<div class=\"contain-to-grid sticky\">\n    <div data-options=\"sticky_on: large\" data-topbar=\"\" class=\"top-bar\">\n        <ul class=\"title-area\">\n            <li class=\"name\">\n                <h1>\n                        ");
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(1, program1, data),contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "home", options) : helperMissing.call(depth0, "link-to", "home", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                </h1>\n            </li>\n            <li class=\"toggle-topbar menu-icon\">\n                <a href=\"javascript:;\"><span>Menu</span></a>\n            </li>\n        </ul>\n\n\n        <section class=\"top-bar-section\">\n            <!-- Left Nav Section -->\n\n");
    stack1 = helpers['if'].call(depth0, "session.isAuthenticated", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(3, program3, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n        </section>\n    </div>\n</div>");
    return buffer;
    
  });

});
define('morgana/templates/profile', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1;


    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/profile/-server-side-model-form-field-container', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing;


    data.buffer.push("<div class=\"holder\">\n    <label>\n        <label ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': ("field.required:required")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">");
    data.buffer.push(escapeExpression((helper = helpers['capitalize-string'] || (depth0 && depth0['capitalize-string']),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "field.label", options) : helperMissing.call(depth0, "capitalize-string", "field.label", options))));
    data.buffer.push("</label>\n        <div class=\"row collapse\">\n            <div class=\"small-12 columns\">\n                ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "serverSideModelFormField", {hash:{
      'fieldBinding': ("field"),
      'modelBinding': ("model")
    },hashTypes:{'fieldBinding': "STRING",'modelBinding': "STRING"},hashContexts:{'fieldBinding': depth0,'modelBinding': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n            </div>\n        </div>\n    </label>\n</div>");
    return buffer;
    
  });

});
define('morgana/templates/profile/-server-side-model-form-fields', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, escapeExpression=this.escapeExpression, self=this;

  function program1(depth0,data) {
    
    var buffer = '';
    data.buffer.push("\n        ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "serverSideModelFormFieldContainer", {hash:{
      'fieldBinding': ("field"),
      'templateName': ("profile/-server-side-model-form-field-container")
    },hashTypes:{'fieldBinding': "STRING",'templateName': "STRING"},hashContexts:{'fieldBinding': depth0,'templateName': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n    ");
    return buffer;
    }

    data.buffer.push("\n<fieldset>\n    ");
    stack1 = helpers.each.call(depth0, "field", "in", "fields", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(1, program1, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n</fieldset>\n");
    return buffer;
    
  });

});
define('morgana/templates/profile/edit-company', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing;


    data.buffer.push("<section>\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Edit Organization\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n\n        <form ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "edit", {hash:{
      'on': ("submit")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(" data-abide>\n            <section class=\"large-8 small-12 columns\">\n                ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "serverSideModelFormFields", {hash:{
      'templateName': ("profile/-server-side-model-form-fields")
    },hashTypes:{'templateName': "STRING"},hashContexts:{'templateName': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n            </section>\n\n            <aside class=\"small-12 large-4 columns\">\n                <div data-ax-fixed-container>\n                    ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.back"),
      'buttonText': ("Back to Profile"),
      'action': ("back")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                    ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.edit"),
      'buttonText': ("Save Organization"),
      'action': ("edit")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                </div>\n            </aside>\n        </form>\n\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/profile/edit-user', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing;


    data.buffer.push("<section id=\"content_project_wizard\">\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Edit User\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n\n        <section class=\"large-8 small-12 columns\">\n            <form ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "edit", {hash:{
      'on': ("submit")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(" data-abide>\n                <div class=\"holder\">\n                    <label class=\"required\" for=\"id_first_name\">First Name</label>\n                    ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'value': ("model.firstName"),
      'id': ("id_first_name"),
      'class': ("textinput"),
      'required': (true),
      'autofocus': ("")
    },hashTypes:{'value': "ID",'id': "STRING",'class': "STRING",'required': "BOOLEAN",'autofocus': "STRING"},hashContexts:{'value': depth0,'id': depth0,'class': depth0,'required': depth0,'autofocus': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("\n                    <small class=\"error\">This field is required.</small>\n                </div>\n                <div class=\"holder\">\n                    <label class=\"required\" for=\"id_last_name\">Last Name</label>\n                    ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'value': ("model.lastName"),
      'id': ("id_last_name"),
      'class': ("textinput"),
      'required': (true)
    },hashTypes:{'value': "ID",'id': "STRING",'class': "STRING",'required': "BOOLEAN"},hashContexts:{'value': depth0,'id': depth0,'class': depth0,'required': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("\n                    <small class=\"error\">This field is required.</small>\n                </div>\n            </form>\n        </section>\n        <aside class=\"small-12 large-4 columns\">\n            ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.back"),
      'buttonText': ("Back to Profile"),
      'action': ("back")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.edit"),
      'buttonText': ("Save User"),
      'action': ("edit")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n        </aside>\n\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/profile/index', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing;


    data.buffer.push("<section>\n\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Profile\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n        <section class=\"large-8 small-12 columns\">\n\n            <section>\n                <table>\n                    <tbody>\n                        <tr>\n                            <th class=\"text-right\">Email:</th>\n                            <td>");
    stack1 = helpers._triageMustache.call(depth0, "currentUser.email", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n                        </tr>\n                        <tr>\n                            <th class=\"text-right\">Name:</th>\n                            <td>");
    stack1 = helpers._triageMustache.call(depth0, "currentUser.fullName", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n                        </tr>\n                        <tr>\n                            <th class=\"text-right\">API token:</th>\n                            <td>");
    stack1 = helpers._triageMustache.call(depth0, "currentUser.authToken", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n                        </tr>\n                        <tr>\n                            <th class=\"text-right\">AX rest api:</th>\n                            <td><a ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'href': ("currentUser.apiUrl")
    },hashTypes:{'href': "ID"},hashContexts:{'href': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">");
    stack1 = helpers._triageMustache.call(depth0, "currentUser.apiUrl", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</a></td>\n                        </tr>\n                        <tr>\n                            <th class=\"text-right\">API Example Calls/Doc</th>\n                            <td><a href=\"http://blog.ax-semantics.com/pages/apidoc.html\">http://blog.ax-semantics.com/pages/apidoc.html</a></td>\n                        </tr>\n                    </tbody>\n\n                </table>\n                    <h4>Organization information</h4>\n                    ");
    data.buffer.push(escapeExpression((helper = helpers['field-detail'] || (depth0 && depth0['field-detail']),options={hash:{
      'fields': ("fields"),
      'model': ("model")
    },hashTypes:{'fields': "ID",'model': "ID"},hashContexts:{'fields': depth0,'model': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "field-detail", options))));
    data.buffer.push("\n\n            </section>\n        </section>\n        <aside class=\"small-12 large-4 columns\">\n            <div>\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.editUser"),
      'buttonText': ("Edit User"),
      'action': ("editUser")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.editCompany"),
      'buttonText': ("Edit Organization"),
      'action': ("editCompany")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            </div>\n\n        </aside>\n\n\n    </div>\n</section>\n");
    return buffer;
    
  });

});
define('morgana/templates/tags', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1;


    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/tags/-filtered-thing-list', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing, self=this;

  function program1(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n    <form ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "searchFields", {hash:{
      'on': ("submit")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(">\n        <div class=\"row\">\n            <div class=\"small-10 columns\">\n                ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'value': ("searchTerm"),
      'placeholder': ("for UID or Object Name")
    },hashTypes:{'value': "ID",'placeholder': "STRING"},hashContexts:{'value': depth0,'placeholder': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("\n            </div>\n            <div class=\"small-2 columns\">\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.searchFields"),
      'buttonText': ("Search"),
      'action': ("searchFields")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            </div>\n        </div>\n    </form>\n");
    return buffer;
    }

  function program3(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n    ");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "things/-loading", options) : helperMissing.call(depth0, "partial", "things/-loading", options))));
    data.buffer.push("\n");
    return buffer;
    }

  function program5(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n\n");
    stack1 = helpers['if'].call(depth0, "hasItems", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(15, program15, data),fn:self.program(6, program6, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    }
  function program6(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n    <table>\n        <thead>\n            <tr>\n                <th ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "sortField", "tag", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0,depth0],types:["STRING","STRING"],data:data})));
    data.buffer.push(" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":clickable sortFieldData.tag.cssClass")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                    Tag<i class=\"sort-indicator\"/></th>\n                <th ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "sortField", "content_project_pk", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0,depth0],types:["STRING","STRING"],data:data})));
    data.buffer.push(" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":clickable sortFieldData.content_project_pk.cssClass")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                    ContentProject<i class=\"sort-indicator\"/></th>\n\n                <th ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "sortField", "uid", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0,depth0],types:["STRING","STRING"],data:data})));
    data.buffer.push(" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":clickable sortFieldData.uid.cssClass")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                    UID<i class=\"sort-indicator\"/></th>\n\n                ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(7, program7, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "showSkuInTagList", options) : helperMissing.call(depth0, "can-do", "showSkuInTagList", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n                <th ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "sortField", "name", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0,depth0],types:["STRING","STRING"],data:data})));
    data.buffer.push(" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":clickable sortFieldData.name.cssClass")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                    Object<i class=\"sort-indicator\"/></th>\n\n\n                <th ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "sortField", "status", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0,depth0],types:["STRING","STRING"],data:data})));
    data.buffer.push(" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":clickable sortFieldData.status.cssClass")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                    Content Status<i class=\"sort-indicator\"/></th>\n                <th ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "sortField", "most_important_missing_requirement_level", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0,depth0],types:["STRING","STRING"],data:data})));
    data.buffer.push(" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":clickable sortFieldData.most_important_missing_requirement_level.cssClass")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                    Validity<i class=\"sort-indicator\"/></th>\n                <th ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "sortField", "text_length_in_chars", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0,depth0],types:["STRING","STRING"],data:data})));
    data.buffer.push(" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":clickable sortFieldData.text_length_in_chars.cssClass")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                    Text Length<i class=\"sort-indicator\"/></th>\n                <th ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "sortField", "modified", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0,depth0],types:["STRING","STRING"],data:data})));
    data.buffer.push(" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":clickable sortFieldData.modified.cssClass")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                    Modified<i class=\"sort-indicator\"/></th>\n            </tr>\n            <tr>\n                <th>\n                    ");
    stack1 = helpers['if'].call(depth0, "facetFilterTags", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(9, program9, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                </th>\n                <th>\n                    ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "select", {hash:{
      'content': ("facetFilterContentProjects"),
      'optionLabelPath': ("content.displayName"),
      'optionValuePath': ("content"),
      'prompt': ("[ show all ]"),
      'value': ("facetFilterContentProject")
    },hashTypes:{'content': "ID",'optionLabelPath': "STRING",'optionValuePath': "STRING",'prompt': "STRING",'value': "ID"},hashContexts:{'content': depth0,'optionLabelPath': depth0,'optionValuePath': depth0,'prompt': depth0,'value': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n                </th>\n                <th></th>\n                ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(11, program11, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "showSkuInTagList", options) : helperMissing.call(depth0, "can-do", "showSkuInTagList", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                <th></th>\n\n\n                <th>\n                    ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "select", {hash:{
      'content': ("facetFilterStatus_"),
      'optionLabelPath': ("content.displayName"),
      'optionValuePath': ("content"),
      'prompt': ("[ show all ]"),
      'value': ("facetFilterStatus")
    },hashTypes:{'content': "ID",'optionLabelPath': "STRING",'optionValuePath': "STRING",'prompt': "STRING",'value': "ID"},hashContexts:{'content': depth0,'optionLabelPath': depth0,'optionValuePath': depth0,'prompt': depth0,'value': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n                </th>\n                <th>\n                    ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "select", {hash:{
      'content': ("facetFilterValidities"),
      'optionLabelPath': ("content.displayName"),
      'optionValuePath': ("content"),
      'prompt': ("[ show all ]"),
      'value': ("facetFilterValidity")
    },hashTypes:{'content': "ID",'optionLabelPath': "STRING",'optionValuePath': "STRING",'prompt': "STRING",'value': "ID"},hashContexts:{'content': depth0,'optionLabelPath': depth0,'optionValuePath': depth0,'prompt': depth0,'value': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n                </th>\n                <th></th>\n                <th></th>\n            </tr>\n        </thead>\n        <tbody>\n\n            ");
    stack1 = helpers.each.call(depth0, "thing", "in", "model", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(13, program13, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n        <tbody>\n    </table>\n    ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "tableFooter", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data})));
    data.buffer.push("\n");
    return buffer;
    }
  function program7(depth0,data) {
    
    var buffer = '';
    data.buffer.push("\n                    <th ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "sortField", "sku", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0,depth0],types:["STRING","STRING"],data:data})));
    data.buffer.push(" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":clickable sortFieldData.sku.cssClass")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                        Article No<i class=\"sort-indicator\"/></th>\n                ");
    return buffer;
    }

  function program9(depth0,data) {
    
    var buffer = '';
    data.buffer.push("\n                    ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "select", {hash:{
      'content': ("facetFilterTags"),
      'optionLabelPath': ("content.displayName"),
      'optionValuePath': ("content"),
      'prompt': ("[ show all ]"),
      'value': ("facetFilterTag")
    },hashTypes:{'content': "ID",'optionLabelPath': "STRING",'optionValuePath': "STRING",'prompt': "STRING",'value': "ID"},hashContexts:{'content': depth0,'optionLabelPath': depth0,'optionValuePath': depth0,'prompt': depth0,'value': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n                    ");
    return buffer;
    }

  function program11(depth0,data) {
    
    
    data.buffer.push("\n                <th></th>\n                ");
    }

  function program13(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                ");
    data.buffer.push(escapeExpression((helper = helpers.render || (depth0 && depth0.render),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0,depth0],types:["STRING","ID"],data:data},helper ? helper.call(depth0, "tags/thingRequirementLevelDetail", "thing", options) : helperMissing.call(depth0, "render", "tags/thingRequirementLevelDetail", "thing", options))));
    data.buffer.push("\n            ");
    return buffer;
    }

  function program15(depth0,data) {
    
    
    data.buffer.push("\n\n");
    }

    stack1 = helpers['if'].call(depth0, "showSearchTermField", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n");
    stack1 = helpers['if'].call(depth0, "isLoading", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(5, program5, data),fn:self.program(3, program3, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/tags/-thing-requirement-level-detail-row-data', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var stack1, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression, self=this;

  function program1(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n    ");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "things/-loading", options) : helperMissing.call(depth0, "partial", "things/-loading", options))));
    data.buffer.push("\n");
    return buffer;
    }

  function program3(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n\n    <div class=\"row\">\n        <div class=\"small-12 columns\">\n\n            <i>");
    stack1 = helpers._triageMustache.call(depth0, "concreteThing.requirementLevelStatusText", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</i>\n        </div>\n    </div>\n\n    ");
    stack1 = helpers['if'].call(depth0, "concreteThing.hasMissingData", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(4, program4, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n");
    return buffer;
    }
  function program4(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n        <table>\n            ");
    stack1 = helpers.each.call(depth0, "fieldData", "in", "improvableFieldsRequirementLevelData", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(5, program5, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n        </table>\n    ");
    return buffer;
    }
  function program5(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n                <tr>\n                    ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.program(8, program8, data),fn:self.program(6, program6, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "showSkuInTagList", options) : helperMissing.call(depth0, "can-do", "showSkuInTagList", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n                    <td ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":ax-field fieldData.requirementLevelCssClassName fieldData.requirementLevelEmptyCssClassName")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">");
    stack1 = helpers._triageMustache.call(depth0, "fieldData.displayValue", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n                    <td colspan=\"2\"></td>\n                </tr>\n            ");
    return buffer;
    }
  function program6(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n                        <th colspan=\"6\" class=\"text-right\">");
    stack1 = helpers._triageMustache.call(depth0, "fieldData.displayLabel", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</th>\n                    ");
    return buffer;
    }

  function program8(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n                        <th colspan=\"5\" class=\"text-right\">");
    stack1 = helpers._triageMustache.call(depth0, "fieldData.displayLabel", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</th>\n                    ");
    return buffer;
    }

    stack1 = helpers['if'].call(depth0, "showDetailsLoading", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(3, program3, data),fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    else { data.buffer.push(''); }
    
  });

});
define('morgana/templates/tags/index', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing, self=this;

  function program1(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                <div data-dropdown=\"generate_content_drop\" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":dropdown :button :expand actionsLoadingStages.generateContent:loading")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                    <span>\n                        Generate content\n                    </span>\n                    <ul id=\"generate_content_drop\" class=\"f-dropdown content\" data-dropdown-content>\n                        <li>\n                            ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'displayAsButton': (false),
      'isLoading': ("actionsLoadingStages.generateContent"),
      'buttonText': ("Generate all missing content"),
      'action': ("generateContent")
    },hashTypes:{'displayAsButton': "BOOLEAN",'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'displayAsButton': depth0,'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                        </li>\n                        <li>\n                            ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'displayAsButton': (false),
      'isLoading': ("actionsLoadingStages.generateContent"),
      'buttonText': ("(Re-)generate all content"),
      'action': ("forceGenerateContent")
    },hashTypes:{'displayAsButton': "BOOLEAN",'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'displayAsButton': depth0,'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                        </li>\n\n                    </ul>\n                </div>\n\n            ");
    return buffer;
    }

  function program3(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                <div>\n                    ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.buyCredits"),
      'buttonText': ("Buy credits to generate content"),
      'action': ("buyCredits")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                </div>\n            ");
    return buffer;
    }

    data.buffer.push("<section>\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>All objects</h1>\n        </div>\n    </header>\n    <div class=\"row\">\n        <section class=\"large-8 small-12 columns\">\n           ");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "tags/-filtered-thing-list", options) : helperMissing.call(depth0, "partial", "tags/-filtered-thing-list", options))));
    data.buffer.push("\n        </section>\n        <aside class=\"small-12 large-4 columns\">\n            ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.home"),
      'buttonText': ("To Content Projects Overview"),
      'action': ("home")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n\n            ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.program(3, program3, data),fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "payForContent", options) : helperMissing.call(depth0, "can-do", "payForContent", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n            <div>\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.uploadFile"),
      'buttonText': ("Import Objects from File"),
      'action': ("uploadFile")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            </div>\n            <div>\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.downloadContent"),
      'buttonText': ("Download content as Excel"),
      'action': ("downloadContent")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            </div>\n        </aside>\n    </div>\n</section>\n");
    return buffer;
    
  });

});
define('morgana/templates/tags/thing-requirement-level-detail', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, escapeExpression=this.escapeExpression, self=this, helperMissing=helpers.helperMissing;

  function program1(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("<span class=\"notranslate\" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'title': ("thing.tag")
    },hashTypes:{'title': "STRING"},hashContexts:{'title': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">");
    stack1 = helpers._triageMustache.call(depth0, "thing.tag", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</span>");
    return buffer;
    }

  function program3(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n        ");
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(4, program4, data),contexts:[depth0,depth0],types:["STRING","ID"],data:data},helper ? helper.call(depth0, "content-project.index", "thing.contentProject.id", options) : helperMissing.call(depth0, "link-to", "content-project.index", "thing.contentProject.id", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    return buffer;
    }
  function program4(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("<span\n                class=\"notranslate\" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'title': ("thing.contentProject.name")
    },hashTypes:{'title': "STRING"},hashContexts:{'title': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">");
    stack1 = helpers._triageMustache.call(depth0, "thing.contentProject.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</span>");
    return buffer;
    }

  function program6(depth0,data) {
    
    var stack1, helper, options;
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(7, program7, data),contexts:[depth0,depth0,depth0],types:["STRING","ID","ID"],data:data},helper ? helper.call(depth0, "content-project.thing-type.thing.index", "thing.contentProject.id", "thing.id", options) : helperMissing.call(depth0, "link-to", "content-project.thing-type.thing.index", "thing.contentProject.id", "thing.id", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    else { data.buffer.push(''); }
    }
  function program7(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("<span\n            class=\"notranslate\" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'title': ("thing.uid")
    },hashTypes:{'title': "STRING"},hashContexts:{'title': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">");
    stack1 = helpers._triageMustache.call(depth0, "thing.uid", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</span>");
    return buffer;
    }

  function program9(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n        <td>");
    stack1 = helpers['if'].call(depth0, "thing.sku", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(10, program10, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n    ");
    return buffer;
    }
  function program10(depth0,data) {
    
    var stack1, helper, options;
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(11, program11, data),contexts:[depth0,depth0,depth0],types:["STRING","ID","ID"],data:data},helper ? helper.call(depth0, "content-project.thing-type.thing.index", "thing.contentProject.id", "thing.id", options) : helperMissing.call(depth0, "link-to", "content-project.thing-type.thing.index", "thing.contentProject.id", "thing.id", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    else { data.buffer.push(''); }
    }
  function program11(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("<span\n                class=\"notranslate\" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'title': ("thing.sku")
    },hashTypes:{'title': "STRING"},hashContexts:{'title': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">");
    stack1 = helpers._triageMustache.call(depth0, "thing.sku", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</span>");
    return buffer;
    }

  function program13(depth0,data) {
    
    var stack1, helper, options;
    stack1 = (helper = helpers['link-to'] || (depth0 && depth0['link-to']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(14, program14, data),contexts:[depth0,depth0,depth0],types:["STRING","ID","ID"],data:data},helper ? helper.call(depth0, "content-project.thing-type.thing.index", "thing.contentProject.id", "thing.id", options) : helperMissing.call(depth0, "link-to", "content-project.thing-type.thing.index", "thing.contentProject.id", "thing.id", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    else { data.buffer.push(''); }
    }
  function program14(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("<span\n            class=\"notranslate\" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'title': ("thing.name")
    },hashTypes:{'title': "STRING"},hashContexts:{'title': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">");
    stack1 = helpers._triageMustache.call(depth0, "thing.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</span>");
    return buffer;
    }

  function program16(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("<span ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'title': ("thing.status")
    },hashTypes:{'title': "STRING"},hashContexts:{'title': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">");
    stack1 = helpers._triageMustache.call(depth0, "thing.status", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</span>");
    return buffer;
    }

  function program18(depth0,data) {
    
    var buffer = '';
    data.buffer.push("\n        <a href=\"javascript:;\" ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "thingRequirementLevelDetail", "thing", "thing.contentProject", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0,depth0,depth0],types:["STRING","ID","ID"],data:data})));
    data.buffer.push(">\n            <i data-tooltip\n                ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': ("thing.mostImportantMissingRequirementLevelClassName")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push("\n                ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'title': ("thing.requirementLevelStatusText")
    },hashTypes:{'title': "STRING"},hashContexts:{'title': depth0},contexts:[],types:[],data:data})));
    data.buffer.push("\n                    >&nbsp;</i>\n        </a>\n        ");
    return buffer;
    }

  function program20(depth0,data) {
    
    var buffer = '';
    data.buffer.push("\n            <i data-tooltip\n                ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': ("thing.mostImportantMissingRequirementLevelClassName")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push("\n                ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'title': ("thing.requirementLevelStatusText")
    },hashTypes:{'title': "STRING"},hashContexts:{'title': depth0},contexts:[],types:[],data:data})));
    data.buffer.push("\n                    >&nbsp;</i>\n        ");
    return buffer;
    }

  function program22(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n            ");
    stack1 = helpers._triageMustache.call(depth0, "thing.textLengthInChars", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("&nbsp;Chars<br/>\n            (");
    stack1 = helpers._triageMustache.call(depth0, "thing.textLengthInWords", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("&nbsp;Words)\n        ");
    return buffer;
    }

  function program24(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n            ");
    data.buffer.push(escapeExpression((helper = helpers.ago || (depth0 && depth0.ago),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "thing.modified", options) : helperMissing.call(depth0, "ago", "thing.modified", options))));
    data.buffer.push("\n        ");
    return buffer;
    }

  function program26(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n    ");
    stack1 = helpers['if'].call(depth0, "showDetails", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(27, program27, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    }
  function program27(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n\n\n        <tr id=\"requirement-level-detail-filler-row\">\n            ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.program(30, program30, data),fn:self.program(28, program28, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "showSkuInTagList", options) : helperMissing.call(depth0, "can-do", "showSkuInTagList", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n        </tr>\n        <tr id=\"requirement-level-detail-row\">\n            ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.program(34, program34, data),fn:self.program(32, program32, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "showSkuInTagList", options) : helperMissing.call(depth0, "can-do", "showSkuInTagList", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n        </tr>\n\n\n    ");
    return buffer;
    }
  function program28(depth0,data) {
    
    
    data.buffer.push("\n                <td colspan=\"9\"></td>\n            ");
    }

  function program30(depth0,data) {
    
    
    data.buffer.push("\n                <td colspan=\"8\"></td>\n            ");
    }

  function program32(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                <td colspan=\"9\">");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "tags/-thing-requirement-level-detail-row-data", options) : helperMissing.call(depth0, "partial", "tags/-thing-requirement-level-detail-row-data", options))));
    data.buffer.push("</td>\n            ");
    return buffer;
    }

  function program34(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n                <td colspan=\"8\">");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "tags/-thing-requirement-level-detail-row-data", options) : helperMissing.call(depth0, "partial", "tags/-thing-requirement-level-detail-row-data", options))));
    data.buffer.push("</td>\n            ");
    return buffer;
    }

    data.buffer.push("<tr ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "thingDetail", "thing", {hash:{
      'on': ("doubleClick")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0,depth0],types:["STRING","ID"],data:data})));
    data.buffer.push(" class=\"clickable\" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'data-thing-uuid': ("thing.uuid")
    },hashTypes:{'data-thing-uuid': "ID"},hashContexts:{'data-thing-uuid': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n    <td>");
    stack1 = helpers['if'].call(depth0, "thing.tag", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n    <td>");
    stack1 = helpers['if'].call(depth0, "thing.contentProject.name", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(3, program3, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n    </td>\n    <td>");
    stack1 = helpers['if'].call(depth0, "thing.uid", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(6, program6, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n    ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(9, program9, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "showSkuInTagList", options) : helperMissing.call(depth0, "can-do", "showSkuInTagList", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n    <td>");
    stack1 = helpers['if'].call(depth0, "thing.name", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(13, program13, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n    <td>");
    stack1 = helpers['if'].call(depth0, "thing.status", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(16, program16, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n    <td>\n        ");
    stack1 = helpers['if'].call(depth0, "hasDetails", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(20, program20, data),fn:self.program(18, program18, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n    </td>\n    <td>\n        ");
    stack1 = helpers['if'].call(depth0, "thing.textLengthInChars", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(22, program22, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n    </td>\n    <td>\n        ");
    stack1 = helpers['if'].call(depth0, "thing.modified", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(24, program24, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n    </td>\n</tr>\n\n");
    stack1 = helpers['if'].call(depth0, "hasDetails", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(26, program26, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    return buffer;
    
  });

});
define('morgana/templates/tags/upload', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing, self=this;

  function program1(depth0,data) {
    
    
    data.buffer.push("\n                ");
    }

  function program3(depth0,data) {
    
    var buffer = '';
    data.buffer.push("\n                <fieldset>\n                    <div class=\"holder\">\n                        <label for=\"content_project\">Content Project</label>\n                        ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "select", {hash:{
      'content': ("allContentProjects"),
      'optionLabelPath': ("content.name"),
      'optionValuePath': ("content"),
      'prompt': ("Select a Content Project"),
      'selection': ("contentProject"),
      'id': ("content_project")
    },hashTypes:{'content': "ID",'optionLabelPath': "STRING",'optionValuePath': "STRING",'prompt': "STRING",'selection': "ID",'id': "STRING"},hashContexts:{'content': depth0,'optionLabelPath': depth0,'optionValuePath': depth0,'prompt': depth0,'selection': depth0,'id': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n                    </div>\n                </fieldset>\n                ");
    return buffer;
    }

    data.buffer.push("<section id=\"content_project_wizard\">\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>Bulk Upload File\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n        <form ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "upload", {hash:{
      'on': ("submit")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(" data-abide>\n\n            <section class=\"large-8 small-12 columns\">\n                <fieldset>\n                    <div class=\"holder\" id=\"div_id_tag\">\n                        <label for=\"id_tag\">Tag</label>\n                        ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'value': ("tag"),
      'id': ("id_tag"),
      'class': ("textinput"),
      'placeholder': ("KWxx")
    },hashTypes:{'value': "ID",'id': "STRING",'class': "STRING",'placeholder': "STRING"},hashContexts:{'value': depth0,'id': depth0,'class': depth0,'placeholder': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("\n                    </div>\n                    <div class=\"holder\" id=\"div_id_data_file\">\n                        <label for=\"id_data_file\">File</label>\n                        ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "FileUploadField", {hash:{
      'uploadFile': ("dataFile")
    },hashTypes:{'uploadFile': "ID"},hashContexts:{'uploadFile': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n                    </div>\n                </fieldset>\n                ");
    stack1 = (helper = helpers['can-do'] || (depth0 && depth0['can-do']),options={hash:{},hashTypes:{},hashContexts:{},inverse:self.program(3, program3, data),fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "multiContentProjectUploads", options) : helperMissing.call(depth0, "can-do", "multiContentProjectUploads", options));
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n            </section>\n\n            <aside class=\"small-12 large-4 columns\">\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.back"),
      'buttonText': ("Back to Import List"),
      'action': ("back")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.upload"),
      'buttonText': ("Upload File"),
      'action': ("upload")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            </aside>\n        </form>\n    </div>\n</section>\n");
    return buffer;
    
  });

});
define('morgana/templates/thing', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1;


    stack1 = helpers._triageMustache.call(depth0, "outlet", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/things/-loading', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    


    data.buffer.push("<section>\n   <div class=\"row\">\n       <div class=\"small-12 columns text-center\">\n            <img src=\"/assets/ax-template/svg/ax-loader.min.svg\" class=\"small-12 medium-4\" alt=\"\" style=\"width: 100px;\" />\n            <h2>Loading...</h2>\n       </div>\n   </div>\n</section>");
    
  });

});
define('morgana/templates/things/_thing_list', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing, self=this;

  function program1(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n    <form ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "searchFields", {hash:{
      'on': ("submit")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(">\n        <div class=\"row\">\n            <div class=\"small-10 columns\">\n                ");
    data.buffer.push(escapeExpression((helper = helpers.input || (depth0 && depth0.input),options={hash:{
      'value': ("searchTerm"),
      'placeholder': ("Search for UID or Object Name")
    },hashTypes:{'value': "ID",'placeholder': "STRING"},hashContexts:{'value': depth0,'placeholder': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "input", options))));
    data.buffer.push("\n            </div>\n            <div class=\"small-2 columns\">\n                ");
    data.buffer.push(escapeExpression((helper = helpers['button-with-loader'] || (depth0 && depth0['button-with-loader']),options={hash:{
      'isLoading': ("actionsLoadingStages.searchFields"),
      'buttonText': ("Search"),
      'action': ("searchFields")
    },hashTypes:{'isLoading': "ID",'buttonText': "STRING",'action': "STRING"},hashContexts:{'isLoading': depth0,'buttonText': depth0,'action': depth0},contexts:[],types:[],data:data},helper ? helper.call(depth0, options) : helperMissing.call(depth0, "button-with-loader", options))));
    data.buffer.push("\n            </div>\n        </div>\n    </form>\n");
    return buffer;
    }

  function program3(depth0,data) {
    
    var buffer = '', helper, options;
    data.buffer.push("\n    ");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "things/_loading", options) : helperMissing.call(depth0, "partial", "things/_loading", options))));
    data.buffer.push("\n");
    return buffer;
    }

  function program5(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n\n    ");
    stack1 = helpers['if'].call(depth0, "hasItems", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(11, program11, data),fn:self.program(6, program6, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    }
  function program6(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n        ");
    stack1 = helpers['if'].call(depth0, "contentProject.engineConfiguration.status.infoObjects", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(7, program7, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n        <table>\n            <thead>\n            <tr>\n                <th ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "sortField", "uid", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0,depth0],types:["STRING","STRING"],data:data})));
    data.buffer.push(" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":clickable sortFieldData.uid.cssClass")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                    UID<i class=\"sort-indicator\"/></th>\n                <th ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "sortField", "name", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0,depth0],types:["STRING","STRING"],data:data})));
    data.buffer.push(" ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': (":clickable sortFieldData.name.cssClass")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push(">\n                    Object<i class=\"sort-indicator\"/></th>\n                <th>Text Status</th>\n                <th>Validity</th>\n            </tr>\n            </thead>\n            <tbody>\n            ");
    stack1 = helpers.each.call(depth0, "thing", "in", "model", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(9, program9, data),contexts:[depth0,depth0,depth0],types:["ID","ID","ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n            <tbody>\n        </table>\n        ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "tableFooter", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data})));
    data.buffer.push("\n    ");
    return buffer;
    }
  function program7(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n            <div class=\"panel-info\">\n                ");
    stack1 = helpers._triageMustache.call(depth0, "contentProject.engineConfiguration.status.infoObjects", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n            </div>\n        ");
    return buffer;
    }

  function program9(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n                <tr ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "thingDetail", "thing", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0,depth0],types:["STRING","ID"],data:data})));
    data.buffer.push(" class=\"clickable\">\n                    <td class=\"notranslate\">");
    stack1 = helpers._triageMustache.call(depth0, "thing.uid", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n                    <td class=\"notranslate\">");
    stack1 = helpers._triageMustache.call(depth0, "thing.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n                    <td>");
    stack1 = helpers._triageMustache.call(depth0, "thing.status", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("</td>\n                    <td>\n                        <i data-tooltip\n                            ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'class': ("thing.mostImportantMissingRequirementLevelClassName")
    },hashTypes:{'class': "STRING"},hashContexts:{'class': depth0},contexts:[],types:[],data:data})));
    data.buffer.push("\n                            ");
    data.buffer.push(escapeExpression(helpers['bind-attr'].call(depth0, {hash:{
      'title': ("thing.requirementLevelStatusText")
    },hashTypes:{'title': "STRING"},hashContexts:{'title': depth0},contexts:[],types:[],data:data})));
    data.buffer.push("\n                                ></i>\n                    </td>\n                </tr>\n            ");
    return buffer;
    }

  function program11(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n\n        ");
    stack1 = helpers['if'].call(depth0, "lastUsedSearchTerm", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(14, program14, data),fn:self.program(12, program12, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n    ");
    return buffer;
    }
  function program12(depth0,data) {
    
    
    data.buffer.push("\n            <div class=\"panel-info\">\n                Your search has not returned any Objects.\n            </div>\n        ");
    }

  function program14(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n            ");
    stack1 = helpers['if'].call(depth0, "contentProject.engineConfiguration.status.infoNoObjects", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(15, program15, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n        ");
    return buffer;
    }
  function program15(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("\n                <div class=\"panel-info\">\n                    ");
    stack1 = helpers._triageMustache.call(depth0, "contentProject.engineConfiguration.status.infoNoObjects", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n                </div>\n            ");
    return buffer;
    }

    stack1 = helpers['if'].call(depth0, "showSearchTermField", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n\n");
    stack1 = helpers['if'].call(depth0, "isLoading", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(5, program5, data),fn:self.program(3, program3, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n");
    return buffer;
    
  });

});
define('morgana/templates/things/index', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, helperMissing=helpers.helperMissing, escapeExpression=this.escapeExpression;


    data.buffer.push("<section id=\"content_project_wizard\">\n    <header class=\"row\">\n        <div class=\"small-12 columns\">\n            <h1>");
    stack1 = helpers._triageMustache.call(depth0, "contentProject.name", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n            </h1>\n        </div>\n    </header>\n    <div class=\"row\">\n        <section class=\"large-8 small-12 columns\">\n            ");
    data.buffer.push(escapeExpression((helper = helpers.partial || (depth0 && depth0.partial),options={hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["STRING"],data:data},helper ? helper.call(depth0, "things/_thing_list", options) : helperMissing.call(depth0, "partial", "things/_thing_list", options))));
    data.buffer.push("\n        </section>\n        <aside class=\"small-12 large-4 columns\">\n\n        </aside>\n    </div>\n</section>");
    return buffer;
    
  });

});
define('morgana/templates/views/table-footer', ['exports', 'ember'], function (exports, Ember) {

  'use strict';

  exports['default'] = Ember['default'].Handlebars.template(function anonymous(Handlebars,depth0,helpers,partials,data) {
  this.compilerInfo = [4,'>= 1.0.0'];
  helpers = this.merge(helpers, Ember['default'].Handlebars.helpers); data = data || {};
    var buffer = '', stack1, helper, options, escapeExpression=this.escapeExpression, helperMissing=helpers.helperMissing, self=this;

  function program1(depth0,data) {
    
    var buffer = '', stack1;
    data.buffer.push("Showing ");
    stack1 = helpers._triageMustache.call(depth0, "itemsPerPage", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" of");
    return buffer;
    }

  function program3(depth0,data) {
    
    var buffer = '';
    data.buffer.push(" \n        <ul class=\"pagination\">\n            <li>\n                <a ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "previous", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(">Previous</a>\n            </li>\n            <li>\n                ");
    data.buffer.push(escapeExpression(helpers.view.call(depth0, "select", {hash:{
      'content': ("allPages"),
      'value': ("selectedPage")
    },hashTypes:{'content': "ID",'value': "ID"},hashContexts:{'content': depth0,'value': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push("\n            </li>\n            <li>\n                <a ");
    data.buffer.push(escapeExpression(helpers.action.call(depth0, "next", {hash:{
      'on': ("click")
    },hashTypes:{'on': "STRING"},hashContexts:{'on': depth0},contexts:[depth0],types:["STRING"],data:data})));
    data.buffer.push(">Next</a>\n            </li>\n        </ul>\n        ");
    return buffer;
    }

  function program5(depth0,data) {
    
    var buffer = '', stack1, helper, options;
    data.buffer.push("\n        <span class=\"text-light\">");
    stack1 = helpers._triageMustache.call(depth0, "totalPages", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" ");
    data.buffer.push(escapeExpression((helper = helpers['pluralize-string'] || (depth0 && depth0['pluralize-string']),options={hash:{
      's': ("page")
    },hashTypes:{'s': "STRING"},hashContexts:{'s': depth0},contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "totalPages", options) : helperMissing.call(depth0, "pluralize-string", "totalPages", options))));
    data.buffer.push("</span>\n        ");
    return buffer;
    }

    data.buffer.push("<div class=\"row\">\n    <div class=\"medium-6 columns text-light\">\n        ");
    stack1 = helpers['if'].call(depth0, "view.hasMoreThanOnePage", {hash:{},hashTypes:{},hashContexts:{},inverse:self.noop,fn:self.program(1, program1, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" ");
    stack1 = helpers._triageMustache.call(depth0, "totalItems", {hash:{},hashTypes:{},hashContexts:{},contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push(" ");
    data.buffer.push(escapeExpression((helper = helpers['pluralize-string'] || (depth0 && depth0['pluralize-string']),options={hash:{
      's': ("object")
    },hashTypes:{'s': "STRING"},hashContexts:{'s': depth0},contexts:[depth0],types:["ID"],data:data},helper ? helper.call(depth0, "totalItems", options) : helperMissing.call(depth0, "pluralize-string", "totalItems", options))));
    data.buffer.push("\n    </div>\n    <div class=\"medium-6 columns text-right\">\n        ");
    stack1 = helpers['if'].call(depth0, "view.hasMoreThanOnePage", {hash:{},hashTypes:{},hashContexts:{},inverse:self.program(5, program5, data),fn:self.program(3, program3, data),contexts:[depth0],types:["ID"],data:data});
    if(stack1 || stack1 === 0) { data.buffer.push(stack1); }
    data.buffer.push("\n    </div>\n</div>\n");
    return buffer;
    
  });

});
define('morgana/tests/adapters/application.jshint', function () {

  'use strict';

  module('JSHint - adapters');
  test('adapters/application.js should pass jshint', function() { 
    ok(true, 'adapters/application.js should pass jshint.'); 
  });

});
define('morgana/tests/adapters/ax-company.jshint', function () {

  'use strict';

  module('JSHint - adapters');
  test('adapters/ax-company.js should pass jshint', function() { 
    ok(true, 'adapters/ax-company.js should pass jshint.'); 
  });

});
define('morgana/tests/adapters/bulk-upload-general.jshint', function () {

  'use strict';

  module('JSHint - adapters');
  test('adapters/bulk-upload-general.js should pass jshint', function() { 
    ok(true, 'adapters/bulk-upload-general.js should pass jshint.'); 
  });

});
define('morgana/tests/adapters/bulk-upload.jshint', function () {

  'use strict';

  module('JSHint - adapters');
  test('adapters/bulk-upload.js should pass jshint', function() { 
    ok(true, 'adapters/bulk-upload.js should pass jshint.'); 
  });

});
define('morgana/tests/adapters/content-project-export.jshint', function () {

  'use strict';

  module('JSHint - adapters');
  test('adapters/content-project-export.js should pass jshint', function() { 
    ok(true, 'adapters/content-project-export.js should pass jshint.'); 
  });

});
define('morgana/tests/adapters/content-request.jshint', function () {

  'use strict';

  module('JSHint - adapters');
  test('adapters/content-request.js should pass jshint', function() { 
    ok(true, 'adapters/content-request.js should pass jshint.'); 
  });

});
define('morgana/tests/adapters/django-rest-file.jshint', function () {

  'use strict';

  module('JSHint - adapters');
  test('adapters/django-rest-file.js should pass jshint', function() { 
    ok(true, 'adapters/django-rest-file.js should pass jshint.'); 
  });

});
define('morgana/tests/adapters/image-request.jshint', function () {

  'use strict';

  module('JSHint - adapters');
  test('adapters/image-request.js should pass jshint', function() { 
    ok(true, 'adapters/image-request.js should pass jshint.'); 
  });

});
define('morgana/tests/adapters/text-request.jshint', function () {

  'use strict';

  module('JSHint - adapters');
  test('adapters/text-request.js should pass jshint', function() { 
    ok(true, 'adapters/text-request.js should pass jshint.'); 
  });

});
define('morgana/tests/adapters/thing.jshint', function () {

  'use strict';

  module('JSHint - adapters');
  test('adapters/thing.js should pass jshint', function() { 
    ok(true, 'adapters/thing.js should pass jshint.'); 
  });

});
define('morgana/tests/adapters/user-check-list.jshint', function () {

  'use strict';

  module('JSHint - adapters');
  test('adapters/user-check-list.js should pass jshint', function() { 
    ok(true, 'adapters/user-check-list.js should pass jshint.'); 
  });

});
define('morgana/tests/adapters/user.jshint', function () {

  'use strict';

  module('JSHint - adapters');
  test('adapters/user.js should pass jshint', function() { 
    ok(true, 'adapters/user.js should pass jshint.'); 
  });

});
define('morgana/tests/app.jshint', function () {

  'use strict';

  module('JSHint - .');
  test('app.js should pass jshint', function() { 
    ok(true, 'app.js should pass jshint.'); 
  });

});
define('morgana/tests/authenticators/myax.jshint', function () {

  'use strict';

  module('JSHint - authenticators');
  test('authenticators/myax.js should pass jshint', function() { 
    ok(true, 'authenticators/myax.js should pass jshint.'); 
  });

});
define('morgana/tests/authorizers/myax.jshint', function () {

  'use strict';

  module('JSHint - authorizers');
  test('authorizers/myax.js should pass jshint', function() { 
    ok(true, 'authorizers/myax.js should pass jshint.'); 
  });

});
define('morgana/tests/components/button-with-loader.jshint', function () {

  'use strict';

  module('JSHint - components');
  test('components/button-with-loader.js should pass jshint', function() { 
    ok(true, 'components/button-with-loader.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/application.jshint', function () {

  'use strict';

  module('JSHint - controllers');
  test('controllers/application.js should pass jshint', function() { 
    ok(true, 'controllers/application.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/content-project/bulk-upload/upload.jshint', function () {

  'use strict';

  module('JSHint - controllers/content-project/bulk-upload');
  test('controllers/content-project/bulk-upload/upload.js should pass jshint', function() { 
    ok(true, 'controllers/content-project/bulk-upload/upload.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/content-project/content-project-exports/index.jshint', function () {

  'use strict';

  module('JSHint - controllers/content-project/content-project-exports');
  test('controllers/content-project/content-project-exports/index.js should pass jshint', function() { 
    ok(true, 'controllers/content-project/content-project-exports/index.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/content-project/delete.jshint', function () {

  'use strict';

  module('JSHint - controllers/content-project');
  test('controllers/content-project/delete.js should pass jshint', function() { 
    ok(true, 'controllers/content-project/delete.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/content-project/edit.jshint', function () {

  'use strict';

  module('JSHint - controllers/content-project');
  test('controllers/content-project/edit.js should pass jshint', function() { 
    ok(true, 'controllers/content-project/edit.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/content-project/index.jshint', function () {

  'use strict';

  module('JSHint - controllers/content-project');
  test('controllers/content-project/index.js should pass jshint', function() { 
    ok(true, 'controllers/content-project/index.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/content-project/thing-type/thing-new.jshint', function () {

  'use strict';

  module('JSHint - controllers/content-project/thing-type');
  test('controllers/content-project/thing-type/thing-new.js should pass jshint', function() { 
    ok(true, 'controllers/content-project/thing-type/thing-new.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/content-project/thing-type/thing/delete.jshint', function () {

  'use strict';

  module('JSHint - controllers/content-project/thing-type/thing');
  test('controllers/content-project/thing-type/thing/delete.js should pass jshint', function() { 
    ok(true, 'controllers/content-project/thing-type/thing/delete.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/content-project/thing-type/thing/edit.jshint', function () {

  'use strict';

  module('JSHint - controllers/content-project/thing-type/thing');
  test('controllers/content-project/thing-type/thing/edit.js should pass jshint', function() { 
    ok(true, 'controllers/content-project/thing-type/thing/edit.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/content-project/thing-type/thing/index.jshint', function () {

  'use strict';

  module('JSHint - controllers/content-project/thing-type/thing');
  test('controllers/content-project/thing-type/thing/index.js should pass jshint', function() { 
    ok(true, 'controllers/content-project/thing-type/thing/index.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/content-project/thing-type/thing/server-side-model-field-detail.jshint', function () {

  'use strict';

  module('JSHint - controllers/content-project/thing-type/thing');
  test('controllers/content-project/thing-type/thing/server-side-model-field-detail.js should pass jshint', function() { 
    ok(true, 'controllers/content-project/thing-type/thing/server-side-model-field-detail.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/content-projects/index.jshint', function () {

  'use strict';

  module('JSHint - controllers/content-projects');
  test('controllers/content-projects/index.js should pass jshint', function() { 
    ok(true, 'controllers/content-projects/index.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/credits/credit-history-element.jshint', function () {

  'use strict';

  module('JSHint - controllers/credits');
  test('controllers/credits/credit-history-element.js should pass jshint', function() { 
    ok(true, 'controllers/credits/credit-history-element.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/credits/credit-history.jshint', function () {

  'use strict';

  module('JSHint - controllers/credits');
  test('controllers/credits/credit-history.js should pass jshint', function() { 
    ok(true, 'controllers/credits/credit-history.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/credits/invoices.jshint', function () {

  'use strict';

  module('JSHint - controllers/credits');
  test('controllers/credits/invoices.js should pass jshint', function() { 
    ok(true, 'controllers/credits/invoices.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/download-exports/index.jshint', function () {

  'use strict';

  module('JSHint - controllers/download-exports');
  test('controllers/download-exports/index.js should pass jshint', function() { 
    ok(true, 'controllers/download-exports/index.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/engine-configuration/content-project/new.jshint', function () {

  'use strict';

  module('JSHint - controllers/engine-configuration/content-project');
  test('controllers/engine-configuration/content-project/new.js should pass jshint', function() { 
    ok(true, 'controllers/engine-configuration/content-project/new.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/engine-configuration/index.jshint', function () {

  'use strict';

  module('JSHint - controllers/engine-configuration');
  test('controllers/engine-configuration/index.js should pass jshint', function() { 
    ok(true, 'controllers/engine-configuration/index.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/engine-configurations/contact.jshint', function () {

  'use strict';

  module('JSHint - controllers/engine-configurations');
  test('controllers/engine-configurations/contact.js should pass jshint', function() { 
    ok(true, 'controllers/engine-configurations/contact.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/engine-configurations/index.jshint', function () {

  'use strict';

  module('JSHint - controllers/engine-configurations');
  test('controllers/engine-configurations/index.js should pass jshint', function() { 
    ok(true, 'controllers/engine-configurations/index.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/eventlog/index.jshint', function () {

  'use strict';

  module('JSHint - controllers/eventlog');
  test('controllers/eventlog/index.js should pass jshint', function() { 
    ok(true, 'controllers/eventlog/index.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/flash-messages.jshint', function () {

  'use strict';

  module('JSHint - controllers');
  test('controllers/flash-messages.js should pass jshint', function() { 
    ok(true, 'controllers/flash-messages.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/home/index.jshint', function () {

  'use strict';

  module('JSHint - controllers/home');
  test('controllers/home/index.js should pass jshint', function() { 
    ok(true, 'controllers/home/index.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/login.jshint', function () {

  'use strict';

  module('JSHint - controllers');
  test('controllers/login.js should pass jshint', function() { 
    ok(true, 'controllers/login.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/navigation.jshint', function () {

  'use strict';

  module('JSHint - controllers');
  test('controllers/navigation.js should pass jshint', function() { 
    ok(true, 'controllers/navigation.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/profile/edit-company.jshint', function () {

  'use strict';

  module('JSHint - controllers/profile');
  test('controllers/profile/edit-company.js should pass jshint', function() { 
    ok(true, 'controllers/profile/edit-company.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/profile/edit-user.jshint', function () {

  'use strict';

  module('JSHint - controllers/profile');
  test('controllers/profile/edit-user.js should pass jshint', function() { 
    ok(true, 'controllers/profile/edit-user.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/profile/index.jshint', function () {

  'use strict';

  module('JSHint - controllers/profile');
  test('controllers/profile/index.js should pass jshint', function() { 
    ok(true, 'controllers/profile/index.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/tags/index.jshint', function () {

  'use strict';

  module('JSHint - controllers/tags');
  test('controllers/tags/index.js should pass jshint', function() { 
    ok(true, 'controllers/tags/index.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/tags/thing-requirement-level-detail.jshint', function () {

  'use strict';

  module('JSHint - controllers/tags');
  test('controllers/tags/thing-requirement-level-detail.js should pass jshint', function() { 
    ok(true, 'controllers/tags/thing-requirement-level-detail.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/tags/upload.jshint', function () {

  'use strict';

  module('JSHint - controllers/tags');
  test('controllers/tags/upload.js should pass jshint', function() { 
    ok(true, 'controllers/tags/upload.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/things/index.jshint', function () {

  'use strict';

  module('JSHint - controllers/things');
  test('controllers/things/index.js should pass jshint', function() { 
    ok(true, 'controllers/things/index.js should pass jshint.'); 
  });

});
define('morgana/tests/controllers/user-check-list/index.jshint', function () {

  'use strict';

  module('JSHint - controllers/user-check-list');
  test('controllers/user-check-list/index.js should pass jshint', function() { 
    ok(true, 'controllers/user-check-list/index.js should pass jshint.'); 
  });

});
define('morgana/tests/helpers/can-do.jshint', function () {

  'use strict';

  module('JSHint - helpers');
  test('helpers/can-do.js should pass jshint', function() { 
    ok(true, 'helpers/can-do.js should pass jshint.'); 
  });

});
define('morgana/tests/helpers/capitalize-string.jshint', function () {

  'use strict';

  module('JSHint - helpers');
  test('helpers/capitalize-string.js should pass jshint', function() { 
    ok(true, 'helpers/capitalize-string.js should pass jshint.'); 
  });

});
define('morgana/tests/helpers/field-detail.jshint', function () {

  'use strict';

  module('JSHint - helpers');
  test('helpers/field-detail.js should pass jshint', function() { 
    ok(true, 'helpers/field-detail.js should pass jshint.'); 
  });

});
define('morgana/tests/helpers/flash-messages.jshint', function () {

  'use strict';

  module('JSHint - helpers');
  test('helpers/flash-messages.js should pass jshint', function() { 
    ok(true, 'helpers/flash-messages.js should pass jshint.'); 
  });

});
define('morgana/tests/helpers/pluralize-string.jshint', function () {

  'use strict';

  module('JSHint - helpers');
  test('helpers/pluralize-string.js should pass jshint', function() { 
    ok(true, 'helpers/pluralize-string.js should pass jshint.'); 
  });

});
define('morgana/tests/helpers/resolver', ['exports', 'ember/resolver', 'morgana/config/environment'], function (exports, Resolver, config) {

  'use strict';

  var resolver = Resolver['default'].create();

  resolver.namespace = {
    modulePrefix: config['default'].modulePrefix,
    podModulePrefix: config['default'].podModulePrefix
  };

  exports['default'] = resolver;

});
define('morgana/tests/helpers/resolver.jshint', function () {

  'use strict';

  module('JSHint - helpers');
  test('helpers/resolver.js should pass jshint', function() { 
    ok(true, 'helpers/resolver.js should pass jshint.'); 
  });

});
define('morgana/tests/helpers/start-app', ['exports', 'ember', 'morgana/app', 'morgana/router', 'morgana/config/environment'], function (exports, Ember, Application, Router, config) {

  'use strict';

  function startApp(attrs) {
    var application;

    var attributes = Ember['default'].merge({}, config['default'].APP);
    attributes = Ember['default'].merge(attributes, attrs); // use defaults, but you can override;

    Ember['default'].run(function() {
      application = Application['default'].create(attributes);
      application.setupForTesting();
      application.injectTestHelpers();
    });

    return application;
  }
  exports['default'] = startApp;

});
define('morgana/tests/helpers/start-app.jshint', function () {

  'use strict';

  module('JSHint - helpers');
  test('helpers/start-app.js should pass jshint', function() { 
    ok(true, 'helpers/start-app.js should pass jshint.'); 
  });

});
define('morgana/tests/helpers/text-with-errors.jshint', function () {

  'use strict';

  module('JSHint - helpers');
  test('helpers/text-with-errors.js should pass jshint', function() { 
    ok(true, 'helpers/text-with-errors.js should pass jshint.'); 
  });

});
define('morgana/tests/initializers/flash-messages.jshint', function () {

  'use strict';

  module('JSHint - initializers');
  test('initializers/flash-messages.js should pass jshint', function() { 
    ok(true, 'initializers/flash-messages.js should pass jshint.'); 
  });

});
define('morgana/tests/initializers/myax.jshint', function () {

  'use strict';

  module('JSHint - initializers');
  test('initializers/myax.js should pass jshint', function() { 
    ok(true, 'initializers/myax.js should pass jshint.'); 
  });

});
define('morgana/tests/initializers/server-side-model.jshint', function () {

  'use strict';

  module('JSHint - initializers');
  test('initializers/server-side-model.js should pass jshint', function() { 
    ok(true, 'initializers/server-side-model.js should pass jshint.'); 
  });

});
define('morgana/tests/mixins/django-rest-file-adapter.jshint', function () {

  'use strict';

  module('JSHint - mixins');
  test('mixins/django-rest-file-adapter.js should pass jshint', function() { 
    ok(true, 'mixins/django-rest-file-adapter.js should pass jshint.'); 
  });

});
define('morgana/tests/mixins/flash-message.jshint', function () {

  'use strict';

  module('JSHint - mixins');
  test('mixins/flash-message.js should pass jshint', function() { 
    ok(true, 'mixins/flash-message.js should pass jshint.'); 
  });

});
define('morgana/tests/mixins/flash-messages-route.jshint', function () {

  'use strict';

  module('JSHint - mixins');
  test('mixins/flash-messages-route.js should pass jshint', function() { 
    ok(true, 'mixins/flash-messages-route.js should pass jshint.'); 
  });

});
define('morgana/tests/mixins/jira-report.jshint', function () {

  'use strict';

  module('JSHint - mixins');
  test('mixins/jira-report.js should pass jshint', function() { 
    ok(true, 'mixins/jira-report.js should pass jshint.'); 
  });

});
define('morgana/tests/mixins/loading-stages-controller.jshint', function () {

  'use strict';

  module('JSHint - mixins');
  test('mixins/loading-stages-controller.js should pass jshint', function() { 
    ok(true, 'mixins/loading-stages-controller.js should pass jshint.'); 
  });

});
define('morgana/tests/mixins/loading-stages-route.jshint', function () {

  'use strict';

  module('JSHint - mixins');
  test('mixins/loading-stages-route.js should pass jshint', function() { 
    ok(true, 'mixins/loading-stages-route.js should pass jshint.'); 
  });

});
define('morgana/tests/mixins/pagination.jshint', function () {

  'use strict';

  module('JSHint - mixins');
  test('mixins/pagination.js should pass jshint', function() { 
    ok(true, 'mixins/pagination.js should pass jshint.'); 
  });

});
define('morgana/tests/mixins/permissions.jshint', function () {

  'use strict';

  module('JSHint - mixins');
  test('mixins/permissions.js should pass jshint', function() { 
    ok(true, 'mixins/permissions.js should pass jshint.'); 
  });

});
define('morgana/tests/mixins/server-side-field-error.jshint', function () {

  'use strict';

  module('JSHint - mixins');
  test('mixins/server-side-field-error.js should pass jshint', function() { 
    ok(true, 'mixins/server-side-field-error.js should pass jshint.'); 
  });

});
define('morgana/tests/mixins/server-side-model-adapter.jshint', function () {

  'use strict';

  module('JSHint - mixins');
  test('mixins/server-side-model-adapter.js should pass jshint', function() { 
    ok(true, 'mixins/server-side-model-adapter.js should pass jshint.'); 
  });

});
define('morgana/tests/mixins/server-side-model-fields.jshint', function () {

  'use strict';

  module('JSHint - mixins');
  test('mixins/server-side-model-fields.js should pass jshint', function() { 
    ok(true, 'mixins/server-side-model-fields.js should pass jshint.'); 
  });

});
define('morgana/tests/mixins/server-side-model-serializer.jshint', function () {

  'use strict';

  module('JSHint - mixins');
  test('mixins/server-side-model-serializer.js should pass jshint', function() { 
    ok(true, 'mixins/server-side-model-serializer.js should pass jshint.'); 
  });

});
define('morgana/tests/mixins/server-side-model-store.jshint', function () {

  'use strict';

  module('JSHint - mixins');
  test('mixins/server-side-model-store.js should pass jshint', function() { 
    ok(true, 'mixins/server-side-model-store.js should pass jshint.'); 
  });

});
define('morgana/tests/models/bulk-upload-general.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/bulk-upload-general.js should pass jshint', function() { 
    ok(true, 'models/bulk-upload-general.js should pass jshint.'); 
  });

});
define('morgana/tests/models/bulk-upload.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/bulk-upload.js should pass jshint', function() { 
    ok(true, 'models/bulk-upload.js should pass jshint.'); 
  });

});
define('morgana/tests/models/category.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/category.js should pass jshint', function() { 
    ok(true, 'models/category.js should pass jshint.'); 
  });

});
define('morgana/tests/models/content-project-export.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/content-project-export.js should pass jshint', function() { 
    ok(true, 'models/content-project-export.js should pass jshint.'); 
  });

});
define('morgana/tests/models/content-project.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/content-project.js should pass jshint', function() { 
    ok(true, 'models/content-project.js should pass jshint.'); 
  });

});
define('morgana/tests/models/content-request.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/content-request.js should pass jshint', function() { 
    ok(true, 'models/content-request.js should pass jshint.'); 
  });

});
define('morgana/tests/models/credit-history.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/credit-history.js should pass jshint', function() { 
    ok(true, 'models/credit-history.js should pass jshint.'); 
  });

});
define('morgana/tests/models/engine-configuration-status.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/engine-configuration-status.js should pass jshint', function() { 
    ok(true, 'models/engine-configuration-status.js should pass jshint.'); 
  });

});
define('morgana/tests/models/engine-configuration.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/engine-configuration.js should pass jshint', function() { 
    ok(true, 'models/engine-configuration.js should pass jshint.'); 
  });

});
define('morgana/tests/models/engine-configurations-contact.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/engine-configurations-contact.js should pass jshint', function() { 
    ok(true, 'models/engine-configurations-contact.js should pass jshint.'); 
  });

});
define('morgana/tests/models/engine-content-type-category.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/engine-content-type-category.js should pass jshint', function() { 
    ok(true, 'models/engine-content-type-category.js should pass jshint.'); 
  });

});
define('morgana/tests/models/eventlog.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/eventlog.js should pass jshint', function() { 
    ok(true, 'models/eventlog.js should pass jshint.'); 
  });

});
define('morgana/tests/models/field-requirement-level-data.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/field-requirement-level-data.js should pass jshint', function() { 
    ok(true, 'models/field-requirement-level-data.js should pass jshint.'); 
  });

});
define('morgana/tests/models/image-request.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/image-request.js should pass jshint', function() { 
    ok(true, 'models/image-request.js should pass jshint.'); 
  });

});
define('morgana/tests/models/invoice.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/invoice.js should pass jshint', function() { 
    ok(true, 'models/invoice.js should pass jshint.'); 
  });

});
define('morgana/tests/models/language.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/language.js should pass jshint', function() { 
    ok(true, 'models/language.js should pass jshint.'); 
  });

});
define('morgana/tests/models/model-field-choice.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/model-field-choice.js should pass jshint', function() { 
    ok(true, 'models/model-field-choice.js should pass jshint.'); 
  });

});
define('morgana/tests/models/requirement-level-status.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/requirement-level-status.js should pass jshint', function() { 
    ok(true, 'models/requirement-level-status.js should pass jshint.'); 
  });

});
define('morgana/tests/models/tag.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/tag.js should pass jshint', function() { 
    ok(true, 'models/tag.js should pass jshint.'); 
  });

});
define('morgana/tests/models/text-request.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/text-request.js should pass jshint', function() { 
    ok(true, 'models/text-request.js should pass jshint.'); 
  });

});
define('morgana/tests/models/thing.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/thing.js should pass jshint', function() { 
    ok(true, 'models/thing.js should pass jshint.'); 
  });

});
define('morgana/tests/models/user-check-list.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/user-check-list.js should pass jshint', function() { 
    ok(true, 'models/user-check-list.js should pass jshint.'); 
  });

});
define('morgana/tests/models/user.jshint', function () {

  'use strict';

  module('JSHint - models');
  test('models/user.js should pass jshint', function() { 
    ok(true, 'models/user.js should pass jshint.'); 
  });

});
define('morgana/tests/router.jshint', function () {

  'use strict';

  module('JSHint - .');
  test('router.js should pass jshint', function() { 
    ok(true, 'router.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/application.jshint', function () {

  'use strict';

  module('JSHint - routes');
  test('routes/application.js should pass jshint', function() { 
    ok(true, 'routes/application.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/content-project.jshint', function () {

  'use strict';

  module('JSHint - routes');
  test('routes/content-project.js should pass jshint', function() { 
    ok(true, 'routes/content-project.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/content-project/bulk-upload.jshint', function () {

  'use strict';

  module('JSHint - routes/content-project');
  test('routes/content-project/bulk-upload.js should pass jshint', function() { 
    ok(true, 'routes/content-project/bulk-upload.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/content-project/bulk-upload/upload.jshint', function () {

  'use strict';

  module('JSHint - routes/content-project/bulk-upload');
  test('routes/content-project/bulk-upload/upload.js should pass jshint', function() { 
    ok(true, 'routes/content-project/bulk-upload/upload.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/content-project/content-project-exports.jshint', function () {

  'use strict';

  module('JSHint - routes/content-project');
  test('routes/content-project/content-project-exports.js should pass jshint', function() { 
    ok(true, 'routes/content-project/content-project-exports.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/content-project/content-project-exports/index.jshint', function () {

  'use strict';

  module('JSHint - routes/content-project/content-project-exports');
  test('routes/content-project/content-project-exports/index.js should pass jshint', function() { 
    ok(true, 'routes/content-project/content-project-exports/index.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/content-project/delete.jshint', function () {

  'use strict';

  module('JSHint - routes/content-project');
  test('routes/content-project/delete.js should pass jshint', function() { 
    ok(true, 'routes/content-project/delete.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/content-project/edit.jshint', function () {

  'use strict';

  module('JSHint - routes/content-project');
  test('routes/content-project/edit.js should pass jshint', function() { 
    ok(true, 'routes/content-project/edit.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/content-project/index.jshint', function () {

  'use strict';

  module('JSHint - routes/content-project');
  test('routes/content-project/index.js should pass jshint', function() { 
    ok(true, 'routes/content-project/index.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/content-project/thing-type.jshint', function () {

  'use strict';

  module('JSHint - routes/content-project');
  test('routes/content-project/thing-type.js should pass jshint', function() { 
    ok(true, 'routes/content-project/thing-type.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/content-project/thing-type/thing-new.jshint', function () {

  'use strict';

  module('JSHint - routes/content-project/thing-type');
  test('routes/content-project/thing-type/thing-new.js should pass jshint', function() { 
    ok(true, 'routes/content-project/thing-type/thing-new.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/content-project/thing-type/thing.jshint', function () {

  'use strict';

  module('JSHint - routes/content-project/thing-type');
  test('routes/content-project/thing-type/thing.js should pass jshint', function() { 
    ok(true, 'routes/content-project/thing-type/thing.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/content-project/thing-type/thing/delete.jshint', function () {

  'use strict';

  module('JSHint - routes/content-project/thing-type/thing');
  test('routes/content-project/thing-type/thing/delete.js should pass jshint', function() { 
    ok(true, 'routes/content-project/thing-type/thing/delete.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/content-project/thing-type/thing/edit.jshint', function () {

  'use strict';

  module('JSHint - routes/content-project/thing-type/thing');
  test('routes/content-project/thing-type/thing/edit.js should pass jshint', function() { 
    ok(true, 'routes/content-project/thing-type/thing/edit.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/content-project/thing-type/thing/index.jshint', function () {

  'use strict';

  module('JSHint - routes/content-project/thing-type/thing');
  test('routes/content-project/thing-type/thing/index.js should pass jshint', function() { 
    ok(true, 'routes/content-project/thing-type/thing/index.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/content-projects.jshint', function () {

  'use strict';

  module('JSHint - routes');
  test('routes/content-projects.js should pass jshint', function() { 
    ok(true, 'routes/content-projects.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/credits/index.jshint', function () {

  'use strict';

  module('JSHint - routes/credits');
  test('routes/credits/index.js should pass jshint', function() { 
    ok(true, 'routes/credits/index.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/download-exports.jshint', function () {

  'use strict';

  module('JSHint - routes');
  test('routes/download-exports.js should pass jshint', function() { 
    ok(true, 'routes/download-exports.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/download-exports/index.jshint', function () {

  'use strict';

  module('JSHint - routes/download-exports');
  test('routes/download-exports/index.js should pass jshint', function() { 
    ok(true, 'routes/download-exports/index.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/engine-configuration.jshint', function () {

  'use strict';

  module('JSHint - routes');
  test('routes/engine-configuration.js should pass jshint', function() { 
    ok(true, 'routes/engine-configuration.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/engine-configuration/content-project.jshint', function () {

  'use strict';

  module('JSHint - routes/engine-configuration');
  test('routes/engine-configuration/content-project.js should pass jshint', function() { 
    ok(true, 'routes/engine-configuration/content-project.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/engine-configuration/content-project/new.jshint', function () {

  'use strict';

  module('JSHint - routes/engine-configuration/content-project');
  test('routes/engine-configuration/content-project/new.js should pass jshint', function() { 
    ok(true, 'routes/engine-configuration/content-project/new.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/engine-configuration/index.jshint', function () {

  'use strict';

  module('JSHint - routes/engine-configuration');
  test('routes/engine-configuration/index.js should pass jshint', function() { 
    ok(true, 'routes/engine-configuration/index.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/engine-configurations.jshint', function () {

  'use strict';

  module('JSHint - routes');
  test('routes/engine-configurations.js should pass jshint', function() { 
    ok(true, 'routes/engine-configurations.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/engine-configurations/contact.jshint', function () {

  'use strict';

  module('JSHint - routes/engine-configurations');
  test('routes/engine-configurations/contact.js should pass jshint', function() { 
    ok(true, 'routes/engine-configurations/contact.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/engine-configurations/index.jshint', function () {

  'use strict';

  module('JSHint - routes/engine-configurations');
  test('routes/engine-configurations/index.js should pass jshint', function() { 
    ok(true, 'routes/engine-configurations/index.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/eventlog.jshint', function () {

  'use strict';

  module('JSHint - routes');
  test('routes/eventlog.js should pass jshint', function() { 
    ok(true, 'routes/eventlog.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/eventlog/index.jshint', function () {

  'use strict';

  module('JSHint - routes/eventlog');
  test('routes/eventlog/index.js should pass jshint', function() { 
    ok(true, 'routes/eventlog/index.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/home.jshint', function () {

  'use strict';

  module('JSHint - routes');
  test('routes/home.js should pass jshint', function() { 
    ok(true, 'routes/home.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/home/index.jshint', function () {

  'use strict';

  module('JSHint - routes/home');
  test('routes/home/index.js should pass jshint', function() { 
    ok(true, 'routes/home/index.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/login.jshint', function () {

  'use strict';

  module('JSHint - routes');
  test('routes/login.js should pass jshint', function() { 
    ok(true, 'routes/login.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/profile.jshint', function () {

  'use strict';

  module('JSHint - routes');
  test('routes/profile.js should pass jshint', function() { 
    ok(true, 'routes/profile.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/profile/edit-company.jshint', function () {

  'use strict';

  module('JSHint - routes/profile');
  test('routes/profile/edit-company.js should pass jshint', function() { 
    ok(true, 'routes/profile/edit-company.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/profile/edit-user.jshint', function () {

  'use strict';

  module('JSHint - routes/profile');
  test('routes/profile/edit-user.js should pass jshint', function() { 
    ok(true, 'routes/profile/edit-user.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/profile/index.jshint', function () {

  'use strict';

  module('JSHint - routes/profile');
  test('routes/profile/index.js should pass jshint', function() { 
    ok(true, 'routes/profile/index.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/tags.jshint', function () {

  'use strict';

  module('JSHint - routes');
  test('routes/tags.js should pass jshint', function() { 
    ok(true, 'routes/tags.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/tags/index.jshint', function () {

  'use strict';

  module('JSHint - routes/tags');
  test('routes/tags/index.js should pass jshint', function() { 
    ok(true, 'routes/tags/index.js should pass jshint.'); 
  });

});
define('morgana/tests/routes/tags/upload.jshint', function () {

  'use strict';

  module('JSHint - routes/tags');
  test('routes/tags/upload.js should pass jshint', function() { 
    ok(true, 'routes/tags/upload.js should pass jshint.'); 
  });

});
define('morgana/tests/serializers/application.jshint', function () {

  'use strict';

  module('JSHint - serializers');
  test('serializers/application.js should pass jshint', function() { 
    ok(true, 'serializers/application.js should pass jshint.'); 
  });

});
define('morgana/tests/serializers/content-request.jshint', function () {

  'use strict';

  module('JSHint - serializers');
  test('serializers/content-request.js should pass jshint', function() { 
    ok(true, 'serializers/content-request.js should pass jshint.'); 
  });

});
define('morgana/tests/serializers/eventlog.jshint', function () {

  'use strict';

  module('JSHint - serializers');
  test('serializers/eventlog.js should pass jshint', function() { 
    ok(true, 'serializers/eventlog.js should pass jshint.'); 
  });

});
define('morgana/tests/serializers/image-request.jshint', function () {

  'use strict';

  module('JSHint - serializers');
  test('serializers/image-request.js should pass jshint', function() { 
    ok(true, 'serializers/image-request.js should pass jshint.'); 
  });

});
define('morgana/tests/serializers/text-request.jshint', function () {

  'use strict';

  module('JSHint - serializers');
  test('serializers/text-request.js should pass jshint', function() { 
    ok(true, 'serializers/text-request.js should pass jshint.'); 
  });

});
define('morgana/tests/serializers/thing.jshint', function () {

  'use strict';

  module('JSHint - serializers');
  test('serializers/thing.js should pass jshint', function() { 
    ok(true, 'serializers/thing.js should pass jshint.'); 
  });

});
define('morgana/tests/serializers/user-check-list.jshint', function () {

  'use strict';

  module('JSHint - serializers');
  test('serializers/user-check-list.js should pass jshint', function() { 
    ok(true, 'serializers/user-check-list.js should pass jshint.'); 
  });

});
define('morgana/tests/store.jshint', function () {

  'use strict';

  module('JSHint - .');
  test('store.js should pass jshint', function() { 
    ok(true, 'store.js should pass jshint.'); 
  });

});
define('morgana/tests/test-helper', ['morgana/tests/helpers/resolver', 'ember-qunit'], function (resolver, ember_qunit) {

  'use strict';

  ember_qunit.setResolver(resolver['default']);

});
define('morgana/tests/test-helper.jshint', function () {

  'use strict';

  module('JSHint - .');
  test('test-helper.js should pass jshint', function() { 
    ok(true, 'test-helper.js should pass jshint.'); 
  });

});
define('morgana/tests/transforms/json-string-parsed.jshint', function () {

  'use strict';

  module('JSHint - transforms');
  test('transforms/json-string-parsed.js should pass jshint', function() { 
    ok(true, 'transforms/json-string-parsed.js should pass jshint.'); 
  });

});
define('morgana/tests/transforms/upload-file.jshint', function () {

  'use strict';

  module('JSHint - transforms');
  test('transforms/upload-file.js should pass jshint', function() { 
    ok(true, 'transforms/upload-file.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/adapters/application-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('adapter:application', 'ApplicationAdapter', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var adapter = this.subject();
    assert.ok(adapter);
  });

});
define('morgana/tests/unit/adapters/application-test.jshint', function () {

  'use strict';

  module('JSHint - unit/adapters');
  test('unit/adapters/application-test.js should pass jshint', function() { 
    ok(true, 'unit/adapters/application-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/adapters/ax-company-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('adapter:ax-company', 'AxCompanyAdapter', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var adapter = this.subject();
    assert.ok(adapter);
  });

});
define('morgana/tests/unit/adapters/ax-company-test.jshint', function () {

  'use strict';

  module('JSHint - unit/adapters');
  test('unit/adapters/ax-company-test.js should pass jshint', function() { 
    ok(true, 'unit/adapters/ax-company-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/adapters/bulk-upload-general-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('adapter:bulk-upload-general', 'BulkUploadGeneralAdapter', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var adapter = this.subject();
    assert.ok(adapter);
  });

});
define('morgana/tests/unit/adapters/bulk-upload-general-test.jshint', function () {

  'use strict';

  module('JSHint - unit/adapters');
  test('unit/adapters/bulk-upload-general-test.js should pass jshint', function() { 
    ok(true, 'unit/adapters/bulk-upload-general-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/adapters/bulk-upload-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('adapter:bulk-upload', 'BulkUploadAdapter', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var adapter = this.subject();
    assert.ok(adapter);
  });

});
define('morgana/tests/unit/adapters/bulk-upload-test.jshint', function () {

  'use strict';

  module('JSHint - unit/adapters');
  test('unit/adapters/bulk-upload-test.js should pass jshint', function() { 
    ok(true, 'unit/adapters/bulk-upload-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/adapters/content-project-export-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('adapter:content-project-export', 'ContentProjectExportAdapter', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var adapter = this.subject();
    assert.ok(adapter);
  });

});
define('morgana/tests/unit/adapters/content-project-export-test.jshint', function () {

  'use strict';

  module('JSHint - unit/adapters');
  test('unit/adapters/content-project-export-test.js should pass jshint', function() { 
    ok(true, 'unit/adapters/content-project-export-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/adapters/content-request-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('adapter:content-request', 'ContentRequestAdapter', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var adapter = this.subject();
    assert.ok(adapter);
  });

});
define('morgana/tests/unit/adapters/content-request-test.jshint', function () {

  'use strict';

  module('JSHint - unit/adapters');
  test('unit/adapters/content-request-test.js should pass jshint', function() { 
    ok(true, 'unit/adapters/content-request-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/adapters/django-rest-file-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('adapter:django-rest-file', 'DjangoRestFileAdapter', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var adapter = this.subject();
    assert.ok(adapter);
  });

});
define('morgana/tests/unit/adapters/django-rest-file-test.jshint', function () {

  'use strict';

  module('JSHint - unit/adapters');
  test('unit/adapters/django-rest-file-test.js should pass jshint', function() { 
    ok(true, 'unit/adapters/django-rest-file-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/adapters/image-request-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('adapter:image-request', 'ImageRequestAdapter', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var adapter = this.subject();
    assert.ok(adapter);
  });

});
define('morgana/tests/unit/adapters/image-request-test.jshint', function () {

  'use strict';

  module('JSHint - unit/adapters');
  test('unit/adapters/image-request-test.js should pass jshint', function() { 
    ok(true, 'unit/adapters/image-request-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/adapters/text-request-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('adapter:text-request', 'TextRequestAdapter', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var adapter = this.subject();
    assert.ok(adapter);
  });

});
define('morgana/tests/unit/adapters/text-request-test.jshint', function () {

  'use strict';

  module('JSHint - unit/adapters');
  test('unit/adapters/text-request-test.js should pass jshint', function() { 
    ok(true, 'unit/adapters/text-request-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/adapters/thing-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('adapter:thing', 'ThingAdapter', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var adapter = this.subject();
    assert.ok(adapter);
  });

});
define('morgana/tests/unit/adapters/thing-test.jshint', function () {

  'use strict';

  module('JSHint - unit/adapters');
  test('unit/adapters/thing-test.js should pass jshint', function() { 
    ok(true, 'unit/adapters/thing-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/adapters/user-check-list-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('adapter:user-check-list', 'UserCheckListAdapter', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var adapter = this.subject();
    assert.ok(adapter);
  });

});
define('morgana/tests/unit/adapters/user-check-list-test.jshint', function () {

  'use strict';

  module('JSHint - unit/adapters');
  test('unit/adapters/user-check-list-test.js should pass jshint', function() { 
    ok(true, 'unit/adapters/user-check-list-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/adapters/user-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('adapter:user', 'UserAdapter', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var adapter = this.subject();
    assert.ok(adapter);
  });

});
define('morgana/tests/unit/adapters/user-test.jshint', function () {

  'use strict';

  module('JSHint - unit/adapters');
  test('unit/adapters/user-test.js should pass jshint', function() { 
    ok(true, 'unit/adapters/user-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/components/button-with-loader-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForComponent('button-with-loader', 'ButtonWithLoaderComponent', {
    // specify the other units that are required for this test
    // needs: ['component:foo', 'helper:bar']
  });

  ember_qunit.test('it renders', function(assert) {
    assert.expect(2);

    // creates the component instance
    var component = this.subject();
    assert.equal(component._state, 'preRender');

    // appends the component to the page
    this.append();
    assert.equal(component._state, 'inDOM');
  });

});
define('morgana/tests/unit/components/button-with-loader-test.jshint', function () {

  'use strict';

  module('JSHint - unit/components');
  test('unit/components/button-with-loader-test.js should pass jshint', function() { 
    ok(true, 'unit/components/button-with-loader-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/application-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:application', 'ApplicationController', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/application-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers');
  test('unit/controllers/application-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/application-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/content-project/bulk-upload/upload-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:content-project/bulk-upload/upload', 'ContentProjectBulkUploadUploadController', {
    // Specify the other units that are required for this test.
      needs: ['controller:flash-messages']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/content-project/bulk-upload/upload-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/content-project/bulk-upload');
  test('unit/controllers/content-project/bulk-upload/upload-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/content-project/bulk-upload/upload-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/content-project/content-project-exports/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:content-project/content-project-exports/index', 'ContentProjectContentProjectExportsIndexController', {
    // Specify the other units that are required for this test.
    needs: ['controller:application']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/content-project/content-project-exports/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/content-project/content-project-exports');
  test('unit/controllers/content-project/content-project-exports/index-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/content-project/content-project-exports/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/content-project/delete-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:content-project/delete', 'ContentProjectDeleteController', {
    // Specify the other units that are required for this test.
    needs: ['controller:flash-messages']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/content-project/delete-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/content-project');
  test('unit/controllers/content-project/delete-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/content-project/delete-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/content-project/edit-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:content-project/edit', 'ContentProjectEditController', {
    // Specify the other units that are required for this test.
    needs: ['controller:flash-messages']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/content-project/edit-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/content-project');
  test('unit/controllers/content-project/edit-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/content-project/edit-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/content-project/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:content-project/index', 'ContentProjectIndexController', {
    // Specify the other units that are required for this test.
    needs: ['controller:flash-messages']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/content-project/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/content-project');
  test('unit/controllers/content-project/index-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/content-project/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/content-project/thing-type/thing-new-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:content-project/thing-type/thing-new', 'ContentProjectThingTypeThingNewController', {
    // Specify the other units that are required for this test.
    needs: ['controller:flash-messages']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/content-project/thing-type/thing-new-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/content-project/thing-type');
  test('unit/controllers/content-project/thing-type/thing-new-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/content-project/thing-type/thing-new-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/content-project/thing-type/thing/delete-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:content-project/thing-type/thing/delete', 'ContentProjectThingTypeThingDeleteController', {
    // Specify the other units that are required for this test.
     needs: ['controller:flash-messages']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/content-project/thing-type/thing/delete-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/content-project/thing-type/thing');
  test('unit/controllers/content-project/thing-type/thing/delete-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/content-project/thing-type/thing/delete-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/content-project/thing-type/thing/edit-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:content-project/thing-type/thing/edit', 'ContentProjectThingTypeThingEditController', {
    // Specify the other units that are required for this test.
    needs: ['controller:flash-messages']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/content-project/thing-type/thing/edit-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/content-project/thing-type/thing');
  test('unit/controllers/content-project/thing-type/thing/edit-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/content-project/thing-type/thing/edit-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/content-project/thing-type/thing/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:content-project/thing-type/thing/index', 'ContentProjectThingTypeThingIndexController', {
    // Specify the other units that are required for this test.
    needs: ['controller:flash-messages', 'controller:application']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/content-project/thing-type/thing/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/content-project/thing-type/thing');
  test('unit/controllers/content-project/thing-type/thing/index-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/content-project/thing-type/thing/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/content-project/thing-type/thing/server-side-model-field-detail-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:content-project/thing-type/thing/server-side-model-field-detail', 'ContentProjectThingTypeThingServerSideModelFieldDetailController', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/content-project/thing-type/thing/server-side-model-field-detail-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/content-project/thing-type/thing');
  test('unit/controllers/content-project/thing-type/thing/server-side-model-field-detail-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/content-project/thing-type/thing/server-side-model-field-detail-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/content-projects/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:content-projects/index', 'ContentProjectsIndexController', {
    // Specify the other units that are required for this test.
    needs: ['controller:application']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/content-projects/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/content-projects');
  test('unit/controllers/content-projects/index-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/content-projects/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/credits/credit-history-element-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:credits/credit-history-element', 'CreditsCreditHistoryElementController', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/credits/credit-history-element-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/credits');
  test('unit/controllers/credits/credit-history-element-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/credits/credit-history-element-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/credits/credit-history-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:credits/credit-history', 'CreditsCreditHistoryController', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/credits/credit-history-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/credits');
  test('unit/controllers/credits/credit-history-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/credits/credit-history-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/credits/invoices-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:credits/invoices', 'CreditsInvoicesController', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/credits/invoices-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/credits');
  test('unit/controllers/credits/invoices-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/credits/invoices-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/download-exports/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:download-exports/index', 'DownloadExportsIndexController', {
    // Specify the other units that are required for this test.
    needs: ['controller:application']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/download-exports/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/download-exports');
  test('unit/controllers/download-exports/index-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/download-exports/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/engine-configuration/content-project/new-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:engine-configuration/content-project/new', 'EngineConfigurationContentProjectNewController', {
    // Specify the other units that are required for this test.
    needs: ['controller:flash-messages']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/engine-configuration/content-project/new-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/engine-configuration/content-project');
  test('unit/controllers/engine-configuration/content-project/new-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/engine-configuration/content-project/new-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/engine-configuration/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:engine-configuration/index', 'EngineConfigurationIndexController', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/engine-configuration/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/engine-configuration');
  test('unit/controllers/engine-configuration/index-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/engine-configuration/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/engine-configurations/contact-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:engine-configurations/contact', 'EngineConfigurationsContactController', {
    // Specify the other units that are required for this test.
    needs: ['controller:flash-messages']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/engine-configurations/contact-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/engine-configurations');
  test('unit/controllers/engine-configurations/contact-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/engine-configurations/contact-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/engine-configurations/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:engine-configurations/index', 'EngineConfigurationsIndexController', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/engine-configurations/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/engine-configurations');
  test('unit/controllers/engine-configurations/index-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/engine-configurations/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/eventlog/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:eventlog/index', 'EventlogIndexController', {
    // Specify the other units that are required for this test.
    needs: ['controller:application']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/eventlog/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/eventlog');
  test('unit/controllers/eventlog/index-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/eventlog/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/flash-messages-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:flash-messages', 'FlashMessagesController', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/flash-messages-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers');
  test('unit/controllers/flash-messages-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/flash-messages-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/home/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:home/index', 'HomeIndexController', {
    // Specify the other units that are required for this test.
    needs: ['controller:application']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/home/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/home');
  test('unit/controllers/home/index-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/home/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/login-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:login', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/login-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers');
  test('unit/controllers/login-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/login-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/navigation-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:navigation', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/navigation-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers');
  test('unit/controllers/navigation-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/navigation-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/profile/edit-company-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:profile/edit-company', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
   needs: ['controller:flash-messages']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/profile/edit-company-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/profile');
  test('unit/controllers/profile/edit-company-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/profile/edit-company-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/profile/edit-user-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:profile/edit-user', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
      needs: ['controller:flash-messages']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/profile/edit-user-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/profile');
  test('unit/controllers/profile/edit-user-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/profile/edit-user-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/profile/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:profile/index', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/profile/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/profile');
  test('unit/controllers/profile/index-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/profile/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/tags/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:tags/index', 'TagsIndexController', {
    // Specify the other units that are required for this test.
    needs: ['controller:application', 'controller:flash-messages']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/tags/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/tags');
  test('unit/controllers/tags/index-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/tags/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/tags/thing-requirement-level-detail-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:tags/thing-requirement-level-detail', 'ThingRequirementLevelDetailController', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/tags/thing-requirement-level-detail-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/tags');
  test('unit/controllers/tags/thing-requirement-level-detail-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/tags/thing-requirement-level-detail-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/tags/upload-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:tags/upload', 'TagsUploadController', {
    // Specify the other units that are required for this test.
    needs: ['controller:flash-messages']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/tags/upload-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/tags');
  test('unit/controllers/tags/upload-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/tags/upload-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/things/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:things/index', 'ThingsIndexController', {
    // Specify the other units that are required for this test.
    needs: ['controller:application']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/things/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/things');
  test('unit/controllers/things/index-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/things/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/controllers/user-check-list/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('controller:user-check-list/index', 'UserCheckListIndexController', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var controller = this.subject();
    assert.ok(controller);
  });

});
define('morgana/tests/unit/controllers/user-check-list/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/controllers/user-check-list');
  test('unit/controllers/user-check-list/index-test.js should pass jshint', function() { 
    ok(true, 'unit/controllers/user-check-list/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/helpers/can-do-test', ['morgana/helpers/can-do', 'qunit'], function (can_do, qunit) {

  'use strict';

  qunit.module('CanDoHelper');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var result = can_do.canDo(42);
    assert.ok(result);
  });

});
define('morgana/tests/unit/helpers/can-do-test.jshint', function () {

  'use strict';

  module('JSHint - unit/helpers');
  test('unit/helpers/can-do-test.js should pass jshint', function() { 
    ok(true, 'unit/helpers/can-do-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/helpers/capitalize-string-test', ['morgana/helpers/capitalize-string', 'qunit'], function (capitalize_string, qunit) {

  'use strict';

  qunit.module('CapitalizeStringHelper');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var result = capitalize_string.capitalizeString('hello');
    assert.ok(result === 'Hello');
  });

});
define('morgana/tests/unit/helpers/capitalize-string-test.jshint', function () {

  'use strict';

  module('JSHint - unit/helpers');
  test('unit/helpers/capitalize-string-test.js should pass jshint', function() { 
    ok(true, 'unit/helpers/capitalize-string-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/helpers/field-detail-test', ['morgana/helpers/field-detail', 'qunit'], function (field_detail, qunit) {

  'use strict';

  qunit.module('FieldDetailHelper');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
      var options = {
          hash: {
              fields: [],
              model: null
          }
      },
      result = field_detail.fieldDetail(options);

      assert.ok(result);
  });

});
define('morgana/tests/unit/helpers/field-detail-test.jshint', function () {

  'use strict';

  module('JSHint - unit/helpers');
  test('unit/helpers/field-detail-test.js should pass jshint', function() { 
    ok(true, 'unit/helpers/field-detail-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/helpers/flash-messages-test', ['morgana/helpers/flash-messages', 'qunit'], function (flash_messages, qunit) {

  'use strict';

  qunit.module('FlashMessagesHelper');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var result = flash_messages.flashMessages(42);
    assert.ok(result);
  });

});
define('morgana/tests/unit/helpers/flash-messages-test.jshint', function () {

  'use strict';

  module('JSHint - unit/helpers');
  test('unit/helpers/flash-messages-test.js should pass jshint', function() { 
    ok(true, 'unit/helpers/flash-messages-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/helpers/text-with-errors-test', ['morgana/helpers/text-with-errors', 'qunit'], function (text_with_errors, qunit) {

    'use strict';

    qunit.module('TextWithErrorsHelper');

    // Replace this with your real tests.
    qunit.test('it works', function (assert) {
        var text = 'Text',
            options = {
                hash: {

                }
            },
            result = text_with_errors.textWithErrors(text, options);
        assert.ok(result);
    });

});
define('morgana/tests/unit/helpers/text-with-errors-test.jshint', function () {

  'use strict';

  module('JSHint - unit/helpers');
  test('unit/helpers/text-with-errors-test.js should pass jshint', function() { 
    ok(true, 'unit/helpers/text-with-errors-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/initializers/flash-messages-test', ['ember', 'morgana/initializers/flash-messages', 'qunit'], function (Ember, flash_messages, qunit) {

  'use strict';

  var container, application;

  qunit.module('FlashMessagesInitializer', {
    setup: function() {
      Ember['default'].run(function() {
        container = new Ember['default'].Container();
        application = Ember['default'].Application.create();
        application.deferReadiness();
      });
    }
  });

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    flash_messages.initialize(container, application);

    // you would normally confirm the results of the initializer here
    assert.ok(true);
  });

});
define('morgana/tests/unit/initializers/flash-messages-test.jshint', function () {

  'use strict';

  module('JSHint - unit/initializers');
  test('unit/initializers/flash-messages-test.js should pass jshint', function() { 
    ok(true, 'unit/initializers/flash-messages-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/initializers/myax-test', ['ember', 'morgana/initializers/myax', 'qunit'], function (Ember, myax, qunit) {

  'use strict';

  var container, application;

  qunit.module('MyaxInitializer', {
    beforeEach: function() {
      Ember['default'].run(function() {
        application = Ember['default'].Application.create();
        container = application.__container__;
        application.deferReadiness();
      });
    }
  });

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    myax.initialize(container, application);

    // you would normally confirm the results of the initializer here
    assert.ok(true);
  });

});
define('morgana/tests/unit/initializers/myax-test.jshint', function () {

  'use strict';

  module('JSHint - unit/initializers');
  test('unit/initializers/myax-test.js should pass jshint', function() { 
    ok(true, 'unit/initializers/myax-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/initializers/server-side-model-test', ['ember', 'morgana/initializers/server-side-model', 'qunit'], function (Ember, server_side_model, qunit) {

  'use strict';

  var container, application;

  qunit.module('ServerSideModelInitializer', {
    setup: function() {
      Ember['default'].run(function() {
        container = new Ember['default'].Container();
        application = Ember['default'].Application.create();
        application.deferReadiness();
      });
    }
  });

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    server_side_model.initialize(container, application);

    // you would normally confirm the results of the initializer here
    assert.ok(true);
  });

});
define('morgana/tests/unit/initializers/server-side-model-test.jshint', function () {

  'use strict';

  module('JSHint - unit/initializers');
  test('unit/initializers/server-side-model-test.js should pass jshint', function() { 
    ok(true, 'unit/initializers/server-side-model-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/mixins/django-rest-file-adapter-test', ['ember', 'morgana/mixins/django-rest-file-adapter', 'qunit'], function (Ember, DjangoRestFileAdapterMixin, qunit) {

  'use strict';

  qunit.module('DjangoRestFileAdapterMixin');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var DjangoRestFileAdapterObject = Ember['default'].Object.extend(DjangoRestFileAdapterMixin['default']);
    var subject = DjangoRestFileAdapterObject.create();
    assert.ok(subject);
  });

});
define('morgana/tests/unit/mixins/django-rest-file-adapter-test.jshint', function () {

  'use strict';

  module('JSHint - unit/mixins');
  test('unit/mixins/django-rest-file-adapter-test.js should pass jshint', function() { 
    ok(true, 'unit/mixins/django-rest-file-adapter-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/mixins/flash-message-test', ['ember', 'morgana/mixins/flash-message', 'qunit'], function (Ember, FlashMessageMixin, qunit) {

  'use strict';

  qunit.module('FlashMessageMixin');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var FlashMessageObject = Ember['default'].Object.extend(FlashMessageMixin['default']);
    var subject = FlashMessageObject.create();
    assert.ok(subject);
  });

});
define('morgana/tests/unit/mixins/flash-message-test.jshint', function () {

  'use strict';

  module('JSHint - unit/mixins');
  test('unit/mixins/flash-message-test.js should pass jshint', function() { 
    ok(true, 'unit/mixins/flash-message-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/mixins/flash-messages-route-test', ['ember', 'morgana/mixins/flash-messages-route', 'qunit'], function (Ember, FlashMessagesRouteMixin, qunit) {

  'use strict';

  qunit.module('FlashMessagesRouteMixin');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var FlashMessagesRouteObject = Ember['default'].Object.extend(FlashMessagesRouteMixin['default']);
    var subject = FlashMessagesRouteObject.create();
    assert.ok(subject);
  });

});
define('morgana/tests/unit/mixins/flash-messages-route-test.jshint', function () {

  'use strict';

  module('JSHint - unit/mixins');
  test('unit/mixins/flash-messages-route-test.js should pass jshint', function() { 
    ok(true, 'unit/mixins/flash-messages-route-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/mixins/jira-report-test', ['ember', 'morgana/mixins/jira-report', 'qunit'], function (Ember, JiraReportMixin, qunit) {

  'use strict';

  qunit.module('JiraReportMixin');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var JiraReportObject = Ember['default'].Object.extend(JiraReportMixin['default']);
    var subject = JiraReportObject.create();
    assert.ok(subject);
  });

});
define('morgana/tests/unit/mixins/jira-report-test.jshint', function () {

  'use strict';

  module('JSHint - unit/mixins');
  test('unit/mixins/jira-report-test.js should pass jshint', function() { 
    ok(true, 'unit/mixins/jira-report-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/mixins/loading-stages-controller-test', ['ember', 'morgana/mixins/loading-stages-controller', 'qunit'], function (Ember, LoadingStagesControllerMixin, qunit) {

  'use strict';

  qunit.module('LoadingStagesControllerMixin');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var LoadingStagesControllerObject = Ember['default'].Object.extend(LoadingStagesControllerMixin['default']);
    var subject = LoadingStagesControllerObject.create();
    assert.ok(subject);
  });

});
define('morgana/tests/unit/mixins/loading-stages-controller-test.jshint', function () {

  'use strict';

  module('JSHint - unit/mixins');
  test('unit/mixins/loading-stages-controller-test.js should pass jshint', function() { 
    ok(true, 'unit/mixins/loading-stages-controller-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/mixins/loading-stages-route-test', ['ember', 'morgana/mixins/loading-stages-route', 'qunit'], function (Ember, LoadingStagesRouteMixin, qunit) {

  'use strict';

  qunit.module('LoadingStagesRouteMixin');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var LoadingStagesRouteObject = Ember['default'].Object.extend(LoadingStagesRouteMixin['default']);
    var subject = LoadingStagesRouteObject.create();
    assert.ok(subject);
  });

});
define('morgana/tests/unit/mixins/loading-stages-route-test.jshint', function () {

  'use strict';

  module('JSHint - unit/mixins');
  test('unit/mixins/loading-stages-route-test.js should pass jshint', function() { 
    ok(true, 'unit/mixins/loading-stages-route-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/mixins/pagination-test', ['ember', 'morgana/mixins/pagination', 'qunit'], function (Ember, pagination, qunit) {

  'use strict';

  qunit.module('PaginationMixin');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var PaginationObject = Ember['default'].Object.extend(pagination.PaginationMixin);
    var subject = PaginationObject.create();
    assert.ok(subject);
  });

});
define('morgana/tests/unit/mixins/pagination-test.jshint', function () {

  'use strict';

  module('JSHint - unit/mixins');
  test('unit/mixins/pagination-test.js should pass jshint', function() { 
    ok(true, 'unit/mixins/pagination-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/mixins/permissions-test', ['ember', 'morgana/mixins/permissions', 'qunit'], function (Ember, permissions, qunit) {

  'use strict';

  qunit.module('PermissionsMixin');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var PermissionsObject = Ember['default'].Object.extend(permissions.PermissionsMixin);
    var subject = PermissionsObject.create();
    assert.ok(subject);
  });

});
define('morgana/tests/unit/mixins/permissions-test.jshint', function () {

  'use strict';

  module('JSHint - unit/mixins');
  test('unit/mixins/permissions-test.js should pass jshint', function() { 
    ok(true, 'unit/mixins/permissions-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/mixins/server-side-field-error-test', ['ember', 'morgana/mixins/server-side-field-error', 'qunit'], function (Ember, ServerSideFieldErrorMixin, qunit) {

  'use strict';

  qunit.module('ServerSideFieldErrorMixin');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var ServerSideFieldErrorObject = Ember['default'].Object.extend(ServerSideFieldErrorMixin['default']);
    var subject = ServerSideFieldErrorObject.create();
    assert.ok(subject);
  });

});
define('morgana/tests/unit/mixins/server-side-field-error-test.jshint', function () {

  'use strict';

  module('JSHint - unit/mixins');
  test('unit/mixins/server-side-field-error-test.js should pass jshint', function() { 
    ok(true, 'unit/mixins/server-side-field-error-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/mixins/server-side-model-adapter-test', ['ember', 'morgana/mixins/server-side-model-adapter', 'qunit'], function (Ember, ServerSideModelAdapterMixin, qunit) {

  'use strict';

  qunit.module('ServerSideModelAdapterMixin');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var ServerSideModelAdapterObject = Ember['default'].Object.extend(ServerSideModelAdapterMixin['default']);
    var subject = ServerSideModelAdapterObject.create();
    assert.ok(subject);
  });

});
define('morgana/tests/unit/mixins/server-side-model-adapter-test.jshint', function () {

  'use strict';

  module('JSHint - unit/mixins');
  test('unit/mixins/server-side-model-adapter-test.js should pass jshint', function() { 
    ok(true, 'unit/mixins/server-side-model-adapter-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/mixins/server-side-model-fields-test', ['ember', 'morgana/mixins/server-side-model-fields', 'qunit'], function (Ember, ServerSideModelFieldsMixin, qunit) {

  'use strict';

  qunit.module('ServerSideModelFieldsMixin');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var ServerSideModelFieldsObject = Ember['default'].Object.extend(ServerSideModelFieldsMixin['default']);
    var subject = ServerSideModelFieldsObject.create();
    assert.ok(subject);
  });

});
define('morgana/tests/unit/mixins/server-side-model-fields-test.jshint', function () {

  'use strict';

  module('JSHint - unit/mixins');
  test('unit/mixins/server-side-model-fields-test.js should pass jshint', function() { 
    ok(true, 'unit/mixins/server-side-model-fields-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/mixins/server-side-model-serializer-test', ['ember', 'morgana/mixins/server-side-model-serializer', 'qunit'], function (Ember, ServerSideModelSerializerMixin, qunit) {

  'use strict';

  qunit.module('ServerSideModelSerializerMixin');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var ServerSideModelSerializerObject = Ember['default'].Object.extend(ServerSideModelSerializerMixin['default']);
    var subject = ServerSideModelSerializerObject.create();
    assert.ok(subject);
  });

});
define('morgana/tests/unit/mixins/server-side-model-serializer-test.jshint', function () {

  'use strict';

  module('JSHint - unit/mixins');
  test('unit/mixins/server-side-model-serializer-test.js should pass jshint', function() { 
    ok(true, 'unit/mixins/server-side-model-serializer-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/mixins/server-side-model-store-test', ['ember', 'morgana/mixins/server-side-model-store', 'qunit'], function (Ember, ServerSideModelStoreMixin, qunit) {

  'use strict';

  qunit.module('ServerSideModelStoreMixin');

  // Replace this with your real tests.
  qunit.test('it works', function(assert) {
    var ServerSideModelStoreObject = Ember['default'].Object.extend(ServerSideModelStoreMixin['default']);
    var subject = ServerSideModelStoreObject.create();
    assert.ok(subject);
  });

});
define('morgana/tests/unit/mixins/server-side-model-store-test.jshint', function () {

  'use strict';

  module('JSHint - unit/mixins');
  test('unit/mixins/server-side-model-store-test.js should pass jshint', function() { 
    ok(true, 'unit/mixins/server-side-model-store-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/bulk-upload-general-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('bulk-upload-general', 'BulkUploadGeneral', {
    // Specify the other units that are required for this test.
    needs: ['model:content-project', 'model:engine-configuration', 'model:thing']
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/bulk-upload-general-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/bulk-upload-general-test.js should pass jshint', function() { 
    ok(true, 'unit/models/bulk-upload-general-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/bulk-upload-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('bulk-upload', 'BulkUpload', {
    // Specify the other units that are required for this test.
    needs: ['model:content-project', 'model:engine-configuration', 'model:thing']
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/bulk-upload-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/bulk-upload-test.js should pass jshint', function() { 
    ok(true, 'unit/models/bulk-upload-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/category-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('category', 'Category', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/category-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/category-test.js should pass jshint', function() { 
    ok(true, 'unit/models/category-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/content-project-export-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('content-project-export', 'ContentProjectExport', {
    // Specify the other units that are required for this test.
    needs: ['model:content-project', 'model:engine-configuration', 'model:thing']
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/content-project-export-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/content-project-export-test.js should pass jshint', function() { 
    ok(true, 'unit/models/content-project-export-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/content-project-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('content-project', 'ContentProject', {
    // Specify the other units that are required for this test.
    needs: ['model:engine-configuration', 'model:thing', 'model:engine-configuration-status', 'model:language', 'model:engine-content-type-category']
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/content-project-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/content-project-test.js should pass jshint', function() { 
    ok(true, 'unit/models/content-project-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/content-request-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('content-request', 'ContentRequest', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/content-request-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/content-request-test.js should pass jshint', function() { 
    ok(true, 'unit/models/content-request-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/credit-history-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('credit-history', 'CreditHistory', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/credit-history-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/credit-history-test.js should pass jshint', function() { 
    ok(true, 'unit/models/credit-history-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/engine-configuration-status-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('engine-configuration-status', 'EngineConfigurationStatus', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/engine-configuration-status-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/engine-configuration-status-test.js should pass jshint', function() { 
    ok(true, 'unit/models/engine-configuration-status-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/engine-configuration-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('engine-configuration', 'EngineConfiguration', {
    // Specify the other units that are required for this test.
    needs: ['model:engine-configuration-status', 'model:engine-content-type-category', 'model:language']
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/engine-configuration-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/engine-configuration-test.js should pass jshint', function() { 
    ok(true, 'unit/models/engine-configuration-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/engine-configurations-contact-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('engine-configurations-contact', 'EngineConfigurationsContact', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/engine-configurations-contact-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/engine-configurations-contact-test.js should pass jshint', function() { 
    ok(true, 'unit/models/engine-configurations-contact-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/engine-content-type-category-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('engine-content-type-category', 'EngineContentTypeCategory', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/engine-content-type-category-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/engine-content-type-category-test.js should pass jshint', function() { 
    ok(true, 'unit/models/engine-content-type-category-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/eventlog-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('eventlog', 'Eventlog', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/eventlog-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/eventlog-test.js should pass jshint', function() { 
    ok(true, 'unit/models/eventlog-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/field-requirement-level-data-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('field-requirement-level-data', 'FieldRequirementLevelData', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/field-requirement-level-data-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/field-requirement-level-data-test.js should pass jshint', function() { 
    ok(true, 'unit/models/field-requirement-level-data-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/image-request-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('image-request', 'ImageRequest', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/image-request-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/image-request-test.js should pass jshint', function() { 
    ok(true, 'unit/models/image-request-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/invoice-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('invoice', 'Invoice', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/invoice-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/invoice-test.js should pass jshint', function() { 
    ok(true, 'unit/models/invoice-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/language-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('language', 'Language', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/language-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/language-test.js should pass jshint', function() { 
    ok(true, 'unit/models/language-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/model-field-choice-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('model-field-choice', 'ModelFieldChoice', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/model-field-choice-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/model-field-choice-test.js should pass jshint', function() { 
    ok(true, 'unit/models/model-field-choice-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/requirement-level-status-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('requirement-level-status', 'RequirementLevelStatus', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/requirement-level-status-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/requirement-level-status-test.js should pass jshint', function() { 
    ok(true, 'unit/models/requirement-level-status-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/tag-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('tag', 'Tag', {
    // Specify the other units that are required for this test.
    needs: ['model:content-project', 'model:engine-configuration', 'model:thing']
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/tag-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/tag-test.js should pass jshint', function() { 
    ok(true, 'unit/models/tag-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/text-request-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('text-request', 'TextRequest', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/text-request-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/text-request-test.js should pass jshint', function() { 
    ok(true, 'unit/models/text-request-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/thing-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('thing', 'Thing', {
    // Specify the other units that are required for this test.
    needs: ['model:content-project', 'model:engine-configuration']
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/thing-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/thing-test.js should pass jshint', function() { 
    ok(true, 'unit/models/thing-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/user-check-list-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('user-check-list', 'UserCheckList', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/user-check-list-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/user-check-list-test.js should pass jshint', function() { 
    ok(true, 'unit/models/user-check-list-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/models/user-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleForModel('user', 'User', {
    // Specify the other units that are required for this test.
    needs: []
  });

  ember_qunit.test('it exists', function(assert) {
    var model = this.subject();
    // var store = this.store();
    assert.ok(!!model);
  });

});
define('morgana/tests/unit/models/user-test.jshint', function () {

  'use strict';

  module('JSHint - unit/models');
  test('unit/models/user-test.js should pass jshint', function() { 
    ok(true, 'unit/models/user-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/content-project-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:content-project', 'ContentProjectRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/content-project-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes');
  test('unit/routes/content-project-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/content-project-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/content-project/bulk-upload-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:content-project/bulk-upload', 'ContentProjectBulkUploadRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/content-project/bulk-upload-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/content-project');
  test('unit/routes/content-project/bulk-upload-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/content-project/bulk-upload-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/content-project/bulk-upload/upload-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:content-project/bulk-upload/upload', 'ContentProjectBulkUploadUploadRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/content-project/bulk-upload/upload-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/content-project/bulk-upload');
  test('unit/routes/content-project/bulk-upload/upload-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/content-project/bulk-upload/upload-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/content-project/content-project-exports-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:content-project/content-project-exports', 'ContentProjectContentProjectExportsRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/content-project/content-project-exports-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/content-project');
  test('unit/routes/content-project/content-project-exports-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/content-project/content-project-exports-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/content-project/content-project-exports/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:content-project/content-project-exports/index', 'ContentProjectContentProjectExportsIndexRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/content-project/content-project-exports/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/content-project/content-project-exports');
  test('unit/routes/content-project/content-project-exports/index-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/content-project/content-project-exports/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/content-project/delete-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:content-project/delete', 'ContentProjectDeleteRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/content-project/delete-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/content-project');
  test('unit/routes/content-project/delete-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/content-project/delete-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/content-project/edit-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:content-project/edit', 'ContentProjectEditRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/content-project/edit-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/content-project');
  test('unit/routes/content-project/edit-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/content-project/edit-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/content-project/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:content-project/index', 'ContentProjectIndexRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/content-project/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/content-project');
  test('unit/routes/content-project/index-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/content-project/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/content-project/thing-type-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:content-project/thing-type', 'ContentProjectThingTypeRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/content-project/thing-type-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/content-project');
  test('unit/routes/content-project/thing-type-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/content-project/thing-type-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/content-project/thing-type/thing-new-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:content-project/thing-type/thing-new', 'ContentProjectThingTypeThingNewRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/content-project/thing-type/thing-new-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/content-project/thing-type');
  test('unit/routes/content-project/thing-type/thing-new-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/content-project/thing-type/thing-new-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/content-project/thing-type/thing-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:content-project/thing-type/thing', 'ContentProjectThingTypeThingRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/content-project/thing-type/thing-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/content-project/thing-type');
  test('unit/routes/content-project/thing-type/thing-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/content-project/thing-type/thing-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/content-project/thing-type/thing/delete-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:content-project/thing-type/thing/delete', 'ContentProjectThingTypeThingDeleteRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/content-project/thing-type/thing/delete-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/content-project/thing-type/thing');
  test('unit/routes/content-project/thing-type/thing/delete-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/content-project/thing-type/thing/delete-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/content-project/thing-type/thing/edit-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:content-project/thing-type/thing/edit', 'ContentProjectThingTypeThingEditRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/content-project/thing-type/thing/edit-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/content-project/thing-type/thing');
  test('unit/routes/content-project/thing-type/thing/edit-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/content-project/thing-type/thing/edit-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/content-project/thing-type/thing/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:content-project/thing-type/thing/index', 'ContentProjectThingTypeThingIndexRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/content-project/thing-type/thing/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/content-project/thing-type/thing');
  test('unit/routes/content-project/thing-type/thing/index-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/content-project/thing-type/thing/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/content-projects-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:content-projects', 'ContentProjectsRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/content-projects-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes');
  test('unit/routes/content-projects-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/content-projects-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/credits/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:credits/index', 'CreditsIndexRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/credits/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/credits');
  test('unit/routes/credits/index-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/credits/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/download-exports-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:download-exports', 'DownloadExportsRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/download-exports-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes');
  test('unit/routes/download-exports-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/download-exports-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/download-exports/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:download-exports/index', 'DownloadExportsIndexRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/download-exports/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/download-exports');
  test('unit/routes/download-exports/index-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/download-exports/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/engine-configuration-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:engine-configuration', 'EngineConfigurationRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/engine-configuration-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes');
  test('unit/routes/engine-configuration-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/engine-configuration-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/engine-configuration/content-project-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:engine-configuration/content-project', 'EngineConfigurationContentProjectRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/engine-configuration/content-project-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/engine-configuration');
  test('unit/routes/engine-configuration/content-project-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/engine-configuration/content-project-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/engine-configuration/content-project/new-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:engine-configuration/content-project/new', 'EngineConfigurationContentProjectNewRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/engine-configuration/content-project/new-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/engine-configuration/content-project');
  test('unit/routes/engine-configuration/content-project/new-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/engine-configuration/content-project/new-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/engine-configuration/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:engine-configuration/index', 'EngineConfigurationIndexRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/engine-configuration/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/engine-configuration');
  test('unit/routes/engine-configuration/index-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/engine-configuration/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/engine-configurations-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:engine-configurations', 'EngineConfigurationsRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/engine-configurations-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes');
  test('unit/routes/engine-configurations-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/engine-configurations-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/engine-configurations/contact-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:engine-configurations/contact', 'EngineConfigurationsContactRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/engine-configurations/contact-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/engine-configurations');
  test('unit/routes/engine-configurations/contact-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/engine-configurations/contact-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/engine-configurations/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:engine-configurations/index', 'EngineConfigurationsIndexRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/engine-configurations/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/engine-configurations');
  test('unit/routes/engine-configurations/index-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/engine-configurations/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/eventlog-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:eventlog', 'EventlogRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/eventlog-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes');
  test('unit/routes/eventlog-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/eventlog-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/eventlog/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:eventlog/index', 'EventlogIndexRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/eventlog/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/eventlog');
  test('unit/routes/eventlog/index-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/eventlog/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/home-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:home', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/home-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes');
  test('unit/routes/home-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/home-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/home/index-test', ['ember-qunit'], function (ember_qunit) {

    'use strict';

    ember_qunit.moduleFor('route:home/index', 'HomeIndexRoute', {
        // Specify the other units that are required for this test.
        // needs: ['controller:foo']
    });

    ember_qunit.test('it exists', function (assert) {
        var route = this.subject();
        assert.ok(route);
    });

});
define('morgana/tests/unit/routes/home/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/home');
  test('unit/routes/home/index-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/home/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/login-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:login', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/login-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes');
  test('unit/routes/login-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/login-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/profile-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:profile', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/profile-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes');
  test('unit/routes/profile-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/profile-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/profile/edit-company-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:profile/edit-company', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/profile/edit-company-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/profile');
  test('unit/routes/profile/edit-company-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/profile/edit-company-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/profile/edit-user-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:profile/edit-user', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/profile/edit-user-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/profile');
  test('unit/routes/profile/edit-user-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/profile/edit-user-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/profile/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:profile/index', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/profile/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/profile');
  test('unit/routes/profile/index-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/profile/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/tags-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:tags', 'TagsRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/tags-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes');
  test('unit/routes/tags-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/tags-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/tags/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:tags/index', 'TagsIndexRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/tags/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/tags');
  test('unit/routes/tags/index-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/tags/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/routes/tags/upload-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('route:tags/upload', 'TagsUploadRoute', {
    // Specify the other units that are required for this test.
    // needs: ['controller:foo']
  });

  ember_qunit.test('it exists', function(assert) {
    var route = this.subject();
    assert.ok(route);
  });

});
define('morgana/tests/unit/routes/tags/upload-test.jshint', function () {

  'use strict';

  module('JSHint - unit/routes/tags');
  test('unit/routes/tags/upload-test.js should pass jshint', function() { 
    ok(true, 'unit/routes/tags/upload-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/serializers/application-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('serializer:application', 'ApplicationSerializer', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var serializer = this.subject();
    assert.ok(serializer);
  });

});
define('morgana/tests/unit/serializers/application-test.jshint', function () {

  'use strict';

  module('JSHint - unit/serializers');
  test('unit/serializers/application-test.js should pass jshint', function() { 
    ok(true, 'unit/serializers/application-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/serializers/content-request-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('serializer:content-request', 'ContentRequestSerializer', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var serializer = this.subject();
    assert.ok(serializer);
  });

});
define('morgana/tests/unit/serializers/content-request-test.jshint', function () {

  'use strict';

  module('JSHint - unit/serializers');
  test('unit/serializers/content-request-test.js should pass jshint', function() { 
    ok(true, 'unit/serializers/content-request-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/serializers/eventlog-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('serializer:eventlog', 'EventlogSerializer', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var serializer = this.subject();
    assert.ok(serializer);
  });

});
define('morgana/tests/unit/serializers/eventlog-test.jshint', function () {

  'use strict';

  module('JSHint - unit/serializers');
  test('unit/serializers/eventlog-test.js should pass jshint', function() { 
    ok(true, 'unit/serializers/eventlog-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/serializers/image-request-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('serializer:image-request', 'ImageRequestSerializer', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var serializer = this.subject();
    assert.ok(serializer);
  });

});
define('morgana/tests/unit/serializers/image-request-test.jshint', function () {

  'use strict';

  module('JSHint - unit/serializers');
  test('unit/serializers/image-request-test.js should pass jshint', function() { 
    ok(true, 'unit/serializers/image-request-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/serializers/text-request-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('serializer:text-request', 'TextRequestSerializer', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var serializer = this.subject();
    assert.ok(serializer);
  });

});
define('morgana/tests/unit/serializers/text-request-test.jshint', function () {

  'use strict';

  module('JSHint - unit/serializers');
  test('unit/serializers/text-request-test.js should pass jshint', function() { 
    ok(true, 'unit/serializers/text-request-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/serializers/thing-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('serializer:thing', 'ThingSerializer', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var serializer = this.subject();
    assert.ok(serializer);
  });

});
define('morgana/tests/unit/serializers/thing-test.jshint', function () {

  'use strict';

  module('JSHint - unit/serializers');
  test('unit/serializers/thing-test.js should pass jshint', function() { 
    ok(true, 'unit/serializers/thing-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/serializers/user-check-list-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('serializer:user-check-list', 'UserCheckListSerializer', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var serializer = this.subject();
    assert.ok(serializer);
  });

});
define('morgana/tests/unit/serializers/user-check-list-test.jshint', function () {

  'use strict';

  module('JSHint - unit/serializers');
  test('unit/serializers/user-check-list-test.js should pass jshint', function() { 
    ok(true, 'unit/serializers/user-check-list-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/transforms/json-string-parsed-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('transform:json-string-parsed', 'JsonStringParsedTransform', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var transform = this.subject();
    assert.ok(transform);
  });

  var jsonObj = {
      foo: 'bar',
      baz: ['one', 'two'],
      nested: {object: {deeper: 'level'}}
  };

  ember_qunit.test('it serializes and deserializes a nested object', function (assert) {
      var transform = this.subject();
      assert.deepEqual(jsonObj, transform.deserialize(transform.serialize(jsonObj)));
  });

});
define('morgana/tests/unit/transforms/json-string-parsed-test.jshint', function () {

  'use strict';

  module('JSHint - unit/transforms');
  test('unit/transforms/json-string-parsed-test.js should pass jshint', function() { 
    ok(true, 'unit/transforms/json-string-parsed-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/transforms/upload-file-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('transform:upload-file', 'UploadFileTransform', {
    // Specify the other units that are required for this test.
    // needs: ['serializer:foo']
  });

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var transform = this.subject();
    assert.ok(transform);
  });

});
define('morgana/tests/unit/transforms/upload-file-test.jshint', function () {

  'use strict';

  module('JSHint - unit/transforms');
  test('unit/transforms/upload-file-test.js should pass jshint', function() { 
    ok(true, 'unit/transforms/upload-file-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/application-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:application', 'ApplicationView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/application-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views');
  test('unit/views/application-test.js should pass jshint', function() { 
    ok(true, 'unit/views/application-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/child-view-or-string-test', ['ember-qunit'], function (ember_qunit) {

    'use strict';

    ember_qunit.moduleFor('view:child-view-or-string', 'ChildViewOrStringView');

    // Replace this with your real tests.
    ember_qunit.test('it exists', function (assert) {
        var view = this.subject();
        assert.ok(!!view);
    });

});
define('morgana/tests/unit/views/child-view-or-string-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views');
  test('unit/views/child-view-or-string-test.js should pass jshint', function() { 
    ok(true, 'unit/views/child-view-or-string-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/content-project/content-project-exports-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:content-project/content-project-exports', 'ContentProjectContentProjectExportsView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/content-project/content-project-exports-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/content-project');
  test('unit/views/content-project/content-project-exports-test.js should pass jshint', function() { 
    ok(true, 'unit/views/content-project/content-project-exports-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/content-project/delete-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:content-project/delete', 'ContentProjectDeleteView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/content-project/delete-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/content-project');
  test('unit/views/content-project/delete-test.js should pass jshint', function() { 
    ok(true, 'unit/views/content-project/delete-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/content-project/edit-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:content-project/edit', 'ContentProjectEditView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/content-project/edit-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/content-project');
  test('unit/views/content-project/edit-test.js should pass jshint', function() { 
    ok(true, 'unit/views/content-project/edit-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/content-project/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:content-project/index', 'ContentProjectIndexView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/content-project/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/content-project');
  test('unit/views/content-project/index-test.js should pass jshint', function() { 
    ok(true, 'unit/views/content-project/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/content-project/thing-type/thing-new-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:content-project/thing-type/thing-new', 'ContentProjectThingTypeThingNewView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/content-project/thing-type/thing-new-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/content-project/thing-type');
  test('unit/views/content-project/thing-type/thing-new-test.js should pass jshint', function() { 
    ok(true, 'unit/views/content-project/thing-type/thing-new-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/content-project/thing-type/thing/delete-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:content-project/thing-type/thing/delete', 'ContentProjectThingTypeThingDeleteView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/content-project/thing-type/thing/delete-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/content-project/thing-type/thing');
  test('unit/views/content-project/thing-type/thing/delete-test.js should pass jshint', function() { 
    ok(true, 'unit/views/content-project/thing-type/thing/delete-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/content-project/thing-type/thing/edit-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:content-project/thing-type/thing/edit', 'ContentProjectThingTypeThingEditView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/content-project/thing-type/thing/edit-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/content-project/thing-type/thing');
  test('unit/views/content-project/thing-type/thing/edit-test.js should pass jshint', function() { 
    ok(true, 'unit/views/content-project/thing-type/thing/edit-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/content-project/thing-type/thing/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:content-project/thing-type/thing/index', 'ContentProjectThingTypeThingIndexView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/content-project/thing-type/thing/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/content-project/thing-type/thing');
  test('unit/views/content-project/thing-type/thing/index-test.js should pass jshint', function() { 
    ok(true, 'unit/views/content-project/thing-type/thing/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/credits/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:credits/index', 'CreditsIndexView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/credits/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/credits');
  test('unit/views/credits/index-test.js should pass jshint', function() { 
    ok(true, 'unit/views/credits/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/engine-configuration/content-project/new-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:engine-configuration/content-project/new', 'EngineConfigurationContentProjectNewView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/engine-configuration/content-project/new-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/engine-configuration/content-project');
  test('unit/views/engine-configuration/content-project/new-test.js should pass jshint', function() { 
    ok(true, 'unit/views/engine-configuration/content-project/new-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/engine-configuration/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:engine-configuration/index', 'EngineConfigurationIndexView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/engine-configuration/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/engine-configuration');
  test('unit/views/engine-configuration/index-test.js should pass jshint', function() { 
    ok(true, 'unit/views/engine-configuration/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/engine-configurations/contact/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:engine-configurations/contact/index', 'EngineConfigurationsContactIndexView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/engine-configurations/contact/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/engine-configurations/contact');
  test('unit/views/engine-configurations/contact/index-test.js should pass jshint', function() { 
    ok(true, 'unit/views/engine-configurations/contact/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/engine-configurations/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:engine-configurations/index', 'EngineConfigurationsIndexView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/engine-configurations/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/engine-configurations');
  test('unit/views/engine-configurations/index-test.js should pass jshint', function() { 
    ok(true, 'unit/views/engine-configurations/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/eventlog/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:eventlog/index', 'EventlogIndexView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/eventlog/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/eventlog');
  test('unit/views/eventlog/index-test.js should pass jshint', function() { 
    ok(true, 'unit/views/eventlog/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/file-upload-field-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:file-upload-field', 'FileUploadFieldView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/file-upload-field-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views');
  test('unit/views/file-upload-field-test.js should pass jshint', function() { 
    ok(true, 'unit/views/file-upload-field-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/foundation-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:foundation', 'FoundationView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/foundation-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views');
  test('unit/views/foundation-test.js should pass jshint', function() { 
    ok(true, 'unit/views/foundation-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/home/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:home/index', 'HomeIndexView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/home/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/home');
  test('unit/views/home/index-test.js should pass jshint', function() { 
    ok(true, 'unit/views/home/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/navigation-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:navigation');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/navigation-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views');
  test('unit/views/navigation-test.js should pass jshint', function() { 
    ok(true, 'unit/views/navigation-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/server-side-model-form-field-container-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:server-side-model-form-field-container', 'ServerSideModelFormFieldContainerView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/server-side-model-form-field-container-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views');
  test('unit/views/server-side-model-form-field-container-test.js should pass jshint', function() { 
    ok(true, 'unit/views/server-side-model-form-field-container-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/server-side-model-form-field-indicator-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:server-side-model-form-field-indicator', 'ServerSideModelFormFieldIndicatorView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/server-side-model-form-field-indicator-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views');
  test('unit/views/server-side-model-form-field-indicator-test.js should pass jshint', function() { 
    ok(true, 'unit/views/server-side-model-form-field-indicator-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/server-side-model-form-field-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:server-side-model-form-field', 'ServerSideModelFormFieldView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/server-side-model-form-field-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views');
  test('unit/views/server-side-model-form-field-test.js should pass jshint', function() { 
    ok(true, 'unit/views/server-side-model-form-field-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/server-side-model-form-fields-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:server-side-model-form-fields', 'ServerSideModelFormFieldsView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/server-side-model-form-fields-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views');
  test('unit/views/server-side-model-form-fields-test.js should pass jshint', function() { 
    ok(true, 'unit/views/server-side-model-form-fields-test.js should pass jshint.'); 
  });

});
define('morgana/tests/unit/views/tags/index-test', ['ember-qunit'], function (ember_qunit) {

  'use strict';

  ember_qunit.moduleFor('view:tags/index', 'TagsIndexView');

  // Replace this with your real tests.
  ember_qunit.test('it exists', function(assert) {
    var view = this.subject();
    assert.ok(view);
  });

});
define('morgana/tests/unit/views/tags/index-test.jshint', function () {

  'use strict';

  module('JSHint - unit/views/tags');
  test('unit/views/tags/index-test.js should pass jshint', function() { 
    ok(true, 'unit/views/tags/index-test.js should pass jshint.'); 
  });

});
define('morgana/tests/views/application.jshint', function () {

  'use strict';

  module('JSHint - views');
  test('views/application.js should pass jshint', function() { 
    ok(true, 'views/application.js should pass jshint.'); 
  });

});
define('morgana/tests/views/child-view-or-string.jshint', function () {

  'use strict';

  module('JSHint - views');
  test('views/child-view-or-string.js should pass jshint', function() { 
    ok(true, 'views/child-view-or-string.js should pass jshint.'); 
  });

});
define('morgana/tests/views/content-project/content-project-exports.jshint', function () {

  'use strict';

  module('JSHint - views/content-project');
  test('views/content-project/content-project-exports.js should pass jshint', function() { 
    ok(true, 'views/content-project/content-project-exports.js should pass jshint.'); 
  });

});
define('morgana/tests/views/content-project/delete.jshint', function () {

  'use strict';

  module('JSHint - views/content-project');
  test('views/content-project/delete.js should pass jshint', function() { 
    ok(true, 'views/content-project/delete.js should pass jshint.'); 
  });

});
define('morgana/tests/views/content-project/edit.jshint', function () {

  'use strict';

  module('JSHint - views/content-project');
  test('views/content-project/edit.js should pass jshint', function() { 
    ok(true, 'views/content-project/edit.js should pass jshint.'); 
  });

});
define('morgana/tests/views/content-project/index.jshint', function () {

  'use strict';

  module('JSHint - views/content-project');
  test('views/content-project/index.js should pass jshint', function() { 
    ok(true, 'views/content-project/index.js should pass jshint.'); 
  });

});
define('morgana/tests/views/content-project/thing-type/thing-new.jshint', function () {

  'use strict';

  module('JSHint - views/content-project/thing-type');
  test('views/content-project/thing-type/thing-new.js should pass jshint', function() { 
    ok(true, 'views/content-project/thing-type/thing-new.js should pass jshint.'); 
  });

});
define('morgana/tests/views/content-project/thing-type/thing/delete.jshint', function () {

  'use strict';

  module('JSHint - views/content-project/thing-type/thing');
  test('views/content-project/thing-type/thing/delete.js should pass jshint', function() { 
    ok(true, 'views/content-project/thing-type/thing/delete.js should pass jshint.'); 
  });

});
define('morgana/tests/views/content-project/thing-type/thing/edit.jshint', function () {

  'use strict';

  module('JSHint - views/content-project/thing-type/thing');
  test('views/content-project/thing-type/thing/edit.js should pass jshint', function() { 
    ok(true, 'views/content-project/thing-type/thing/edit.js should pass jshint.'); 
  });

});
define('morgana/tests/views/content-project/thing-type/thing/index.jshint', function () {

  'use strict';

  module('JSHint - views/content-project/thing-type/thing');
  test('views/content-project/thing-type/thing/index.js should pass jshint', function() { 
    ok(true, 'views/content-project/thing-type/thing/index.js should pass jshint.'); 
  });

});
define('morgana/tests/views/credits/index.jshint', function () {

  'use strict';

  module('JSHint - views/credits');
  test('views/credits/index.js should pass jshint', function() { 
    ok(true, 'views/credits/index.js should pass jshint.'); 
  });

});
define('morgana/tests/views/engine-configuration/content-project/new.jshint', function () {

  'use strict';

  module('JSHint - views/engine-configuration/content-project');
  test('views/engine-configuration/content-project/new.js should pass jshint', function() { 
    ok(true, 'views/engine-configuration/content-project/new.js should pass jshint.'); 
  });

});
define('morgana/tests/views/engine-configuration/index.jshint', function () {

  'use strict';

  module('JSHint - views/engine-configuration');
  test('views/engine-configuration/index.js should pass jshint', function() { 
    ok(true, 'views/engine-configuration/index.js should pass jshint.'); 
  });

});
define('morgana/tests/views/engine-configurations/contact/index.jshint', function () {

  'use strict';

  module('JSHint - views/engine-configurations/contact');
  test('views/engine-configurations/contact/index.js should pass jshint', function() { 
    ok(true, 'views/engine-configurations/contact/index.js should pass jshint.'); 
  });

});
define('morgana/tests/views/engine-configurations/index.jshint', function () {

  'use strict';

  module('JSHint - views/engine-configurations');
  test('views/engine-configurations/index.js should pass jshint', function() { 
    ok(true, 'views/engine-configurations/index.js should pass jshint.'); 
  });

});
define('morgana/tests/views/eventlog/index.jshint', function () {

  'use strict';

  module('JSHint - views/eventlog');
  test('views/eventlog/index.js should pass jshint', function() { 
    ok(true, 'views/eventlog/index.js should pass jshint.'); 
  });

});
define('morgana/tests/views/file-upload-field.jshint', function () {

  'use strict';

  module('JSHint - views');
  test('views/file-upload-field.js should pass jshint', function() { 
    ok(true, 'views/file-upload-field.js should pass jshint.'); 
  });

});
define('morgana/tests/views/foundation.jshint', function () {

  'use strict';

  module('JSHint - views');
  test('views/foundation.js should pass jshint', function() { 
    ok(true, 'views/foundation.js should pass jshint.'); 
  });

});
define('morgana/tests/views/home/index.jshint', function () {

  'use strict';

  module('JSHint - views/home');
  test('views/home/index.js should pass jshint', function() { 
    ok(true, 'views/home/index.js should pass jshint.'); 
  });

});
define('morgana/tests/views/navigation.jshint', function () {

  'use strict';

  module('JSHint - views');
  test('views/navigation.js should pass jshint', function() { 
    ok(true, 'views/navigation.js should pass jshint.'); 
  });

});
define('morgana/tests/views/server-side-model-form-field-container.jshint', function () {

  'use strict';

  module('JSHint - views');
  test('views/server-side-model-form-field-container.js should pass jshint', function() { 
    ok(true, 'views/server-side-model-form-field-container.js should pass jshint.'); 
  });

});
define('morgana/tests/views/server-side-model-form-field-indicator.jshint', function () {

  'use strict';

  module('JSHint - views');
  test('views/server-side-model-form-field-indicator.js should pass jshint', function() { 
    ok(true, 'views/server-side-model-form-field-indicator.js should pass jshint.'); 
  });

});
define('morgana/tests/views/server-side-model-form-field.jshint', function () {

  'use strict';

  module('JSHint - views');
  test('views/server-side-model-form-field.js should pass jshint', function() { 
    ok(true, 'views/server-side-model-form-field.js should pass jshint.'); 
  });

});
define('morgana/tests/views/server-side-model-form-fields.jshint', function () {

  'use strict';

  module('JSHint - views');
  test('views/server-side-model-form-fields.js should pass jshint', function() { 
    ok(true, 'views/server-side-model-form-fields.js should pass jshint.'); 
  });

});
define('morgana/tests/views/table-footer.jshint', function () {

  'use strict';

  module('JSHint - views');
  test('views/table-footer.js should pass jshint', function() { 
    ok(true, 'views/table-footer.js should pass jshint.'); 
  });

});
define('morgana/tests/views/tags/index.jshint', function () {

  'use strict';

  module('JSHint - views/tags');
  test('views/tags/index.js should pass jshint', function() { 
    ok(true, 'views/tags/index.js should pass jshint.'); 
  });

});
define('morgana/transforms/json-string-parsed', ['exports', 'ember-data'], function (exports, DS) {

  'use strict';

  exports['default'] = DS['default'].Transform.extend({
    deserialize: function (serialized) {
          return JSON.parse(serialized);
      },
      serialize: function (deserialized) {
          return JSON.stringify(deserialized, null, 2);
      }
  });

});
define('morgana/transforms/upload-file', ['exports', 'ember-data'], function (exports, DS) {

  'use strict';

  exports['default'] = DS['default'].Transform.extend({
    deserialize: function(serialized) {
      return serialized;
    },

    serialize: function(deserialized) {
      return deserialized.content;
    }
  });

});
define('morgana/views/application', ['exports', 'ember'], function (exports, Ember) {

	'use strict';

	exports['default'] = Ember['default'].View.extend({
	});

});
define('morgana/views/child-view-or-string', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].ContainerView.extend({
        init: function () {
            this._super();
            this.createChildViews();
        },
        tagName: '',
        createChildViews: function () {
            var self = this,
                content = self.get('content') || '',
                ret;

            if (typeof content === 'string') {
                ret = Ember['default'].View.create({
                    template: Ember['default'].Handlebars.compile(content),
                    tagName: ''
                });
            } else {
                ret = content;
            }

            this.pushObject(ret);
        }

    });

});
define('morgana/views/content-project/content-project-exports', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({
	});

});
define('morgana/views/content-project/delete', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({
	});

});
define('morgana/views/content-project/edit', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({
	});

});
define('morgana/views/content-project/index', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({
	});

});
define('morgana/views/content-project/thing-type/thing-new', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({
	});

});
define('morgana/views/content-project/thing-type/thing/delete', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({
	});

});
define('morgana/views/content-project/thing-type/thing/edit', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({
	});

});
define('morgana/views/content-project/thing-type/thing/index', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({

	});

});
define('morgana/views/credits/index', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({

	});

});
define('morgana/views/engine-configuration/content-project/new', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({
	});

});
define('morgana/views/engine-configuration/index', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({
	});

});
define('morgana/views/engine-configurations/contact/index', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({
	});

});
define('morgana/views/engine-configurations/index', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({
	});

});
define('morgana/views/eventlog/index', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({
	});

});
define('morgana/views/file-upload-field', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].TextField.extend({
        tagName: 'input',
        attributeBindings: ['uploadFile'],
        type: 'file',
        uploadFile: null,
        change: function (e) {
            var reader = new FileReader(),
                that = this;

            Ember['default'].run(function () {
                var fileInfo = e.target.files[0];
                that.set('uploadFile.name', fileInfo.name);
                that.set('uploadFile.size', fileInfo.size);
                that.set('uploadFile.type', fileInfo.type);
                that.set('uploadFile.content', fileInfo);
            });
            return reader.readAsDataURL(e.target.files[0]);
        }
    });

});
define('morgana/views/foundation', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].View.extend({
        didInsertElement : function () {
            this._super();
            Ember['default'].run.scheduleOnce('afterRender', this, this.afterRenderEvent);
        },
        afterRenderEvent : function () {
            Ember['default'].$(document).foundation();
            return;
        }
    });

});
define('morgana/views/home/index', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({
	});

});
define('morgana/views/navigation', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].View.extend({
        tagName: 'nav',
        classNames: ['container', 'navigationRow'],
        templateName: 'navigation'
    });

});
define('morgana/views/server-side-model-form-field-container', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].View.extend({
        model: null,
        init: function () {
            this._super();
        },
        templateName: 'content-project/thing-type/thing/-server-side-model-form-field-container',

        axFieldLevelClass: Ember['default'].computed('field.requirement_level', function () {
            return 'ax-field-level-' + this.get('field.requirement_level');
        }),

        axFieldValidClass: Ember['default'].computed('controller.model', 'field.fieldName', function () {
            return this.get('controller.' + this.get('field.fieldName')) ? 'ax-field-not-empty' : 'ax-field-empty';
        })
    });

});
define('morgana/views/server-side-model-form-field-indicator', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].ContainerView.extend({
        init: function () {
            this._super();
            this.createChildViews();
        },

        axFieldLevelClass: Ember['default'].computed('field.requirement_level', function () {
            return 'ax-field-level-' + this.get('field.requirement_level');
        }),

        createChildViews: function () {
            var ret,
                self = this,
                model = this.get("model"),
                fieldName = this.get('field.fieldName'),
                axEmptyBindingStr;

            if (this.get('field.type') === 'choice') {
                axEmptyBindingStr = 'model.' + fieldName + '.id:ax-field-not-empty:ax-field-empty';
            } else {
                axEmptyBindingStr = 'model.' + fieldName + ':ax-field-not-empty:ax-field-empty';
            }

            ret = Ember['default'].View.create({
                tagName: 'span',
                model: model,

                classNameBindings: [
                    ':postfix',
                    ':' + self.get('axFieldLevelClass'),
                    axEmptyBindingStr
                ]
            });
            this.pushObject(ret);
        }

    });

});
define('morgana/views/server-side-model-form-field', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].ContainerView.extend({
        model: null,

        init: function () {
            this._super();
            this.createChildViews();
        },


        createChildViews: function () {
            var ret,
                content,
                required = this.get('field.required'),
                model = this.get("model"),
                store = this.get('controller.store'),
                fieldName = this.get('field.fieldName'),
                fieldType = this.get('field.type'),
                readOnly = this.get('field.read_only'),
                placeholder = [this.get('field.help_text'), '[' + this.get('field.field_name') + ']'].join(' ');

            if (readOnly) {
                return;
            }
            switch (fieldType) {

            case 'url':
                ret = Ember['default'].TextField.create({
                    model: model,
                    valueBinding: 'model.' + fieldName,
                    type: 'url',
                    'data-tooltip': '',
                    required: required,
                    placeholder: placeholder,
                    title: placeholder,
                    classNames: ['has-tip'],
                    attributeBindings: ['data-tooltip']
                });
                break;
            case 'decimal':
            case 'integer':
                ret = Ember['default'].TextField.create({
                    model: model,
                    valueBinding: 'model.' + fieldName,
                    type: 'number',
                    'data-tooltip': '',
                    required: required,
                    placeholder: placeholder,
                    title: placeholder,
                    classNames: ['has-tip'],
                    attributeBindings: ['data-tooltip']
                });
                break;
            case 'boolean':
                ret = Ember['default'].Select.create({
                    model: model,
                    valueBinding: 'model.' + fieldName,
                    prompt: 'Unknown',
                    optionValuePath: "content.value",
                    optionLabelPath: "content.displayName",
                    content: [
                        {value: true, displayName: 'Yes'},
                        {value: false, displayName: 'No'}
                    ],
                    'data-tooltip': '',
                    required: required,
                    title: placeholder,
                    classNames: ['has-tip'],
                    attributeBindings: ['data-tooltip', 'title']
                });
                break;
            case 'choice':
                content = store.all(model.constructor.typeKey + 'Choice' + Ember['default'].String.capitalize(fieldName));
                ret = Ember['default'].Select.create({
                    model: model,
                    valueBinding: 'model.' + fieldName,
                    prompt: 'Unknown',
                    optionLabelPath: "content.displayName",
                    content: content,
                    'data-tooltip': '',
                    required: required,
                    title: placeholder,
                    classNames: ['has-tip'],
                    attributeBindings: ['data-tooltip', 'title']
                });
                break;
            case 'string':
                ret = Ember['default'].TextField.create({
                    model: model,
                    valueBinding: 'model.' + fieldName,
                    type: 'text',
                    'data-tooltip': '',
                    required: required,
                    placeholder: placeholder,
                    title: placeholder,
                    classNames: ['has-tip'],
                    attributeBindings: ['data-tooltip']
                });
                break;

            case 'json':
                ret = Ember['default'].TextArea.create({
                    model: model,
                    valueBinding: 'model.' + fieldName,
                    'data-tooltip': '',
                    required: required,
                    placeholder: placeholder,
                    title: placeholder,
                    classNames: ['has-tip'],
                    attributeBindings: ['data-tooltip']
                });
                break;
            default:
                ret = Ember['default'].TextField.create({
                    model: model,
                    valueBinding: 'model.' + fieldName,
                    type: 'text',
                    'data-tooltip': '',
                    required: required,
                    placeholder: placeholder,
                    title: placeholder,
                    classNames: ['has-tip'],
                    attributeBindings: ['data-tooltip']

                });
                break;
            }
            ret.reopen({

            });

            this.pushObject(ret);


        }
    });

});
define('morgana/views/server-side-model-form-fields', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].View.extend({
        templateName: 'content-project/thing-type/thing/-server-side-model-form-fields',
        model: null
    });

});
define('morgana/views/table-footer', ['exports', 'ember'], function (exports, Ember) {

    'use strict';

    exports['default'] = Ember['default'].View.extend({
        templateName: 'views/table-footer',
        hasMoreThanOnePage: Ember['default'].computed('controller.totalPages', function(){
            return this.get('controller.totalPages') > 1;
        })
    });

});
define('morgana/views/tags/index', ['exports', 'morgana/views/foundation'], function (exports, FoundationView) {

	'use strict';

	exports['default'] = FoundationView['default'].extend({
	});

});
/* jshint ignore:start */

/* jshint ignore:end */

/* jshint ignore:start */

define('morgana/config/environment', ['ember'], function(Ember) {
  return { 'default': {"modulePrefix":"morgana","environment":"development","baseURL":"/","locationType":"hash","restAdapter":{"namespace":"api/v1","host":"http://0.0.0.0:4200"},"EmberENV":{"FEATURES":{}},"APP":{"rootElement":"#main-rendered-content","LOG_ACTIVE_GENERATION":true,"LOG_VIEW_LOOKUPS":true},"simple-auth":{"routeAfterAuthentication":"home.index","routeIfAlreadyAuthenticated":"home.index","authenticationRoute":"login","sessionPropertyName":"session","authorizer":"authorizer:myax","serverTokenEndpoint":"http://0.0.0.0:4200/api/v1/session/","store":"simple-auth-session-store:local-storage","crossOriginWhitelist":["http://0.0.0.0:4200"]},"contentSecurityPolicyHeader":"Content-Security-Policy","contentSecurityPolicy":{"default-src":"'self' http://0.0.0.0:4200","script-src":"'self' 'unsafe-eval'","font-src":"'self'","connect-src":"'self'","img-src":"'self'","style-src":"'self'","media-src":"'self'"},"exportApplicationGlobal":true}};
});

if (runningTests) {
  require("morgana/tests/test-helper");
} else {
  require("morgana/app")["default"].create({"rootElement":"#main-rendered-content","LOG_ACTIVE_GENERATION":true,"LOG_VIEW_LOOKUPS":true});
}

/* jshint ignore:end */
//# sourceMappingURL=morgana.map