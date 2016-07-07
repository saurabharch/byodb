'use strict';

window.app = angular.module('FullstackGeneratedApp', ['fsaPreBuilt', 'ui.router', 'ui.bootstrap', 'ngAnimate']);

app.config(function ($urlRouterProvider, $locationProvider) {
    // This turns off hashbang urls (/#about) and changes it to something normal (/about)
    $locationProvider.html5Mode(true);
    // If we go to a URL that ui-router doesn't have registered, go to the "/" url.
    $urlRouterProvider.otherwise('/');
    // Trigger page refresh when accessing an OAuth route
    $urlRouterProvider.when('/auth/:provider', function () {
        window.location.reload();
    });
});

// This app.run is for controlling access to specific states.
app.run(function ($rootScope, AuthService, $state) {

    // The given state requires an authenticated user.
    var destinationStateRequiresAuth = function destinationStateRequiresAuth(state) {
        return state.data && state.data.authenticate;
    };

    // $stateChangeStart is an event fired
    // whenever the process of changing a state begins.
    $rootScope.$on('$stateChangeStart', function (event, toState, toParams) {

        if (!destinationStateRequiresAuth(toState)) {
            // The destination state does not require authentication
            // Short circuit with return.
            return;
        }

        if (AuthService.isAuthenticated()) {
            // The user is authenticated.
            // Short circuit with return.
            return;
        }

        // Cancel navigating to new state.
        event.preventDefault();

        AuthService.getLoggedInUser().then(function (user) {
            // If a user is retrieved, then renavigate to the destination
            // (the second time, AuthService.isAuthenticated() will work)
            // otherwise, if no user is logged in, go to "login" state.
            if (user) {
                $state.go(toState.name, toParams);
            } else {
                $state.go('login');
            }
        });
    });
});

app.config(function ($stateProvider) {

    // Register our *about* state.
    $stateProvider.state('about', {
        url: '/about',
        controller: 'AboutController',
        templateUrl: 'js/about/about.html'
    });
});

app.controller('AboutController', function ($scope, FullstackPics) {

    // Images of beautiful Fullstack people.
    $scope.images = _.shuffle(FullstackPics);
});
app.controller('CreatedbCtrl', function ($scope, $state, CreatedbFactory) {

    $scope.createdDB = false;
    $scope.columnArray = [];

    $scope.add = function () {
        $scope.columnArray.push('1');
    };

    $scope.createDB = function (name) {
        CreatedbFactory.createDB(name).then(function (data) {
            $scope.createdDB = data;
        });
    };

    $scope.createTable = function (table, DB) {
        CreatedbFactory.createTable(table, DB);
        $state.go('Table', { dbName: $scope.createdDB.dbName }, { reload: true });
    };
});

app.factory('CreatedbFactory', function ($http) {

    var CreatedbFactory = {};

    function resToData(res) {
        return res.data;
    }

    CreatedbFactory.createDB = function (dbName) {
        return $http.post('/api/masterdb', dbName).then(resToData);
    };

    CreatedbFactory.createTable = function (table, createdDB) {
        table.dbName = createdDB.dbName;
        return $http.post('/api/clientdb', table).then(resToData);
    };

    return CreatedbFactory;
});

app.config(function ($stateProvider) {
    $stateProvider.state('createdb', {
        url: '/createdb',
        templateUrl: 'js/createdb/createdb.html',
        controller: 'CreatedbCtrl',
        resolve: {
            loggedInUser: function loggedInUser(AuthService) {
                return AuthService.getLoggedInUser();
            }
        }
    });
});
app.config(function ($stateProvider) {
    $stateProvider.state('docs', {
        url: '/docs',
        templateUrl: 'js/docs/docs.html'
    });
});

(function () {

    'use strict';

    // Hope you didn't forget Angular! Duh-doy.

    if (!window.angular) throw new Error('I can\'t find Angular!');

    var app = angular.module('fsaPreBuilt', []);

    app.factory('Socket', function () {
        if (!window.io) throw new Error('socket.io not found!');
        return window.io(window.location.origin);
    });

    // AUTH_EVENTS is used throughout our app to
    // broadcast and listen from and to the $rootScope
    // for important events about authentication flow.
    app.constant('AUTH_EVENTS', {
        loginSuccess: 'auth-login-success',
        loginFailed: 'auth-login-failed',
        logoutSuccess: 'auth-logout-success',
        sessionTimeout: 'auth-session-timeout',
        notAuthenticated: 'auth-not-authenticated',
        notAuthorized: 'auth-not-authorized'
    });

    app.factory('AuthInterceptor', function ($rootScope, $q, AUTH_EVENTS) {
        var statusDict = {
            401: AUTH_EVENTS.notAuthenticated,
            403: AUTH_EVENTS.notAuthorized,
            419: AUTH_EVENTS.sessionTimeout,
            440: AUTH_EVENTS.sessionTimeout
        };
        return {
            responseError: function responseError(response) {
                $rootScope.$broadcast(statusDict[response.status], response);
                return $q.reject(response);
            }
        };
    });

    app.config(function ($httpProvider) {
        $httpProvider.interceptors.push(['$injector', function ($injector) {
            return $injector.get('AuthInterceptor');
        }]);
    });

    app.service('AuthService', function ($http, Session, $rootScope, AUTH_EVENTS, $q) {

        function onSuccessfulLogin(response) {
            var data = response.data;
            Session.create(data.id, data.user);
            $rootScope.$broadcast(AUTH_EVENTS.loginSuccess);
            return data.user;
        }

        // Uses the session factory to see if an
        // authenticated user is currently registered.
        this.isAuthenticated = function () {
            return !!Session.user;
        };

        this.getLoggedInUser = function (fromServer) {

            // If an authenticated session exists, we
            // return the user attached to that session
            // with a promise. This ensures that we can
            // always interface with this method asynchronously.

            // Optionally, if true is given as the fromServer parameter,
            // then this cached value will not be used.

            if (this.isAuthenticated() && fromServer !== true) {
                return $q.when(Session.user);
            }

            // Make request GET /session.
            // If it returns a user, call onSuccessfulLogin with the response.
            // If it returns a 401 response, we catch it and instead resolve to null.
            return $http.get('/session').then(onSuccessfulLogin).catch(function () {
                return null;
            });
        };

        this.signup = function (credentials) {
            return $http.post('/signup', credentials).then(onSuccessfulLogin).catch(function () {
                return $q.reject({ message: 'Invalid signup credentials.' });
            });
        };

        this.login = function (credentials) {
            return $http.post('/login', credentials).then(onSuccessfulLogin).catch(function () {
                return $q.reject({ message: 'Invalid login credentials.' });
            });
        };

        this.logout = function () {
            return $http.get('/logout').then(function () {
                Session.destroy();
                $rootScope.$broadcast(AUTH_EVENTS.logoutSuccess);
            });
        };
    });

    app.service('Session', function ($rootScope, AUTH_EVENTS) {

        var self = this;

        $rootScope.$on(AUTH_EVENTS.notAuthenticated, function () {
            self.destroy();
        });

        $rootScope.$on(AUTH_EVENTS.sessionTimeout, function () {
            self.destroy();
        });

        this.id = null;
        this.user = null;

        this.create = function (sessionId, user) {
            this.id = sessionId;
            this.user = user;
        };

        this.destroy = function () {
            this.id = null;
            this.user = null;
        };
    });
})();

app.controller('HomeCtrl', function ($scope, allDbs, $state) {

    $scope.allDbs = allDbs;
});

app.factory('HomeFactory', function ($http) {

    var HomeFactory = {};

    function resToData(res) {
        return res.data;
    }

    HomeFactory.getAllDbs = function () {
        return $http.get('/api/masterdb').then(resToData);
    };

    HomeFactory.deleteDB = function (name) {
        return $http.delete('/api/masterdb/' + name).then(resToData);
    };

    return HomeFactory;
});
app.config(function ($stateProvider) {
    $stateProvider.state('Home', {
        url: '/home',
        templateUrl: 'js/Home/Home.html',
        controller: 'HomeCtrl',
        resolve: {
            allDbs: function allDbs(HomeFactory) {
                return HomeFactory.getAllDbs();
            },
            loggedInUser: function loggedInUser(AuthService) {
                return AuthService.getLoggedInUser();
            }
        }
    });
});
app.config(function ($stateProvider) {
    $stateProvider.state('landingPage', {
        url: '/',
        templateUrl: 'js/landingPage/landingPage.html'
    });
});
app.config(function ($stateProvider) {

    $stateProvider.state('login', {
        url: '/login',
        templateUrl: 'js/login/login.html',
        controller: 'LoginCtrl'
    });
});

app.controller('LoginCtrl', function ($scope, AuthService, $state) {

    $scope.login = {};
    $scope.error = null;

    $scope.sendLogin = function (loginInfo) {

        $scope.error = null;

        AuthService.login(loginInfo).then(function () {
            $state.go('Home');
        }).catch(function () {
            $scope.error = 'Invalid login credentials.';
        });
    };
});

app.config(function ($stateProvider) {

    $stateProvider.state('membersOnly', {
        url: '/members-area',
        template: '<img ng-repeat="item in stash" width="300" ng-src="{{ item }}" />',
        controller: function controller($scope, SecretStash) {
            SecretStash.getStash().then(function (stash) {
                $scope.stash = stash;
            });
        },
        // The following data.authenticate is read by an event listener
        // that controls access to this state. Refer to app.js.
        data: {
            authenticate: true
        }
    });
});

app.factory('SecretStash', function ($http) {

    var getStash = function getStash() {
        return $http.get('/api/members/secret-stash').then(function (response) {
            return response.data;
        });
    };

    return {
        getStash: getStash
    };
});
'use strict';

app.directive('oauthButton', function () {
    return {
        scope: {
            providerName: '@'
        },
        restrict: 'E',
        templateUrl: '/js/oauth/oauth-button.html'
    };
});

app.config(function ($stateProvider) {

    $stateProvider.state('signup', {
        url: '/signup',
        templateUrl: 'js/signup/signup.html',
        controller: 'SignupCtrl'
    });
});

app.controller('SignupCtrl', function ($scope, AuthService, $state) {

    $scope.signup = {};
    $scope.error = null;

    $scope.sendSignup = function (signupInfo) {
        $scope.error = null;
        AuthService.signup(signupInfo).then(function () {
            $state.go('home');
        }).catch(function () {
            $scope.error = 'Oops, cannot sign up with those credentials.';
        });
    };
});

app.controller('AssociationInstanceCtrl', function ($scope, $uibModalInstance, foreignCols, TableFactory, HomeFactory, $stateParams, $state, forTable, forTableName, currTable, colName, id1) {

    $scope.dbName = $stateParams.dbName;

    $scope.singleTable = forTable;

    $scope.TableName = forTableName;

    $scope.currTable = currTable;

    $scope.colName = colName;

    $scope.id1 = id1;

    $scope.setSelected = function () {

        $scope.currRow = this.row;
        console.log($scope.currRow);
    };

    function CreateColumns() {
        $scope.columns = [];
        var table = forTable[0];

        for (var prop in table) {
            if (prop !== 'created_at' && prop !== 'updated_at') {
                $scope.columns.push(prop);
            }
        }
    }

    CreateColumns();

    //this function will re run when the filter function is invoked, in order to repopulate the table
    function CreateRows() {
        $scope.instanceArray = [];
        forTable.forEach(function (row) {
            var rowValues = [];
            for (var prop in row) {
                if (prop !== 'created_at' && prop !== 'updated_at') rowValues.push(row[prop]);
            }
            $scope.instanceArray.push(rowValues);
        });
    }

    // Sort the values in singleTable so that all the values for a given row are grouped
    CreateRows();

    $scope.setForeignKey = function (dbName, tblName, colName, id1, id2) {
        $uibModalInstance.close();
        TableFactory.setForeignKey(dbName, tblName, colName, id1, id2).then(function () {
            $state.go('Table.Single', { dbName: $scope.dbName, tableName: $scope.currTable }, { reload: true });
        });
    };

    $scope.ok = function () {
        $uibModalInstance.close($scope.selected.item);
    };

    $scope.cancel = function () {
        $uibModalInstance.dismiss('cancel');
    };
});
app.controller('deleteDBCtrl', function ($scope, $uibModal, $log) {

    $scope.items = ['item1', 'item2', 'item3'];

    $scope.animationsEnabled = true;

    $scope.open = function (size) {

        var modalInstance = $uibModal.open({
            animation: $scope.animationsEnabled,
            templateUrl: 'deleteDBContent.html',
            controller: 'deleteDBInstanceCtrl',
            size: size,
            resolve: {
                items: function items() {
                    return $scope.items;
                }
            }
        });

        modalInstance.result.then(function (selectedItem) {
            $scope.selected = selectedItem;
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.toggleAnimation = function () {
        $scope.animationsEnabled = !$scope.animationsEnabled;
    };
});

app.controller('deleteDBInstanceCtrl', function ($scope, $uibModalInstance, items, TableFactory, HomeFactory, $stateParams, $state) {

    $scope.dropDbText = 'DROP DATABASE';
    $scope.dbName = $stateParams.dbName;

    $scope.deleteTheDb = function () {
        $uibModalInstance.close($scope.selected.item);
        TableFactory.deleteDb($scope.dbName).then(function () {
            HomeFactory.deleteDB($scope.dbName);
        }).then(function () {
            $state.go('Home', {}, { reload: true });
        });
    };

    $scope.items = items;
    $scope.selected = {
        item: $scope.items[0]
    };

    $scope.ok = function () {
        $uibModalInstance.close($scope.selected.item);
    };

    $scope.cancel = function () {
        $uibModalInstance.dismiss('cancel');
    };
});
app.controller('DeleteDbCtrl', function ($scope) {

    $scope.animationsEnabled = true;

    $scope.open = function (size) {

        var modalInstance = $uibModal.open({
            animation: $scope.animationsEnabled,
            templateUrl: 'deleteDbContent.html',
            controller: 'DeleteDbInstanceCtrl',
            size: size,
            resolve: {
                items: function items() {
                    return $scope.items;
                }
            }
        });

        modalInstance.result.then(function (selectedItem) {
            $scope.selected = selectedItem;
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };
});

app.controller('DeleteDbInstanceCtrl', function ($scope, $uibModalInstance, items, $stateParams, TableFactory) {

    $scope.dbName = $stateParams.dbName;

    $scope.dropDatabase = 'DROP DATABASE';

    $scope.delete = function () {
        TableFactory.deleteDb($scope.dbName);
        // $state.go('Home', {}, {reload : true})
    };

    $scope.cancel = function () {
        $uibModalInstance.dismiss('cancel');
    };
});
app.controller('JoinTableCtrl', function ($scope, TableFactory, $stateParams, joinTable) {

    $scope.joinTable = joinTable;

    function CreateColumns() {
        $scope.columns = [];
        var table = $scope.joinTable[0];

        for (var prop in table) {
            if (prop !== 'created_at' && prop !== 'updated_at') {
                $scope.columns.push(prop);
            }
        }
    }

    CreateColumns();

    //this function will re run when the filter function is invoked, in order to repopulate the table
    function CreateRows() {
        var alias;
        $scope.instanceArray = [];
        joinTable.forEach(function (row) {
            var rowValues = [];
            for (var prop in row) {
                if (prop !== 'created_at' && prop !== 'updated_at') rowValues.push(row[prop]);
            }
            $scope.instanceArray.push(rowValues);
        });
    }

    // Sort the values in singleTable so that all the values for a given row are grouped
    CreateRows();
});
app.controller('QueryTableCtrl', function ($scope, TableFactory, $stateParams) {

    function CreateColumns() {
        $scope.columns = [];
        var table = $scope.joinTable[0];

        for (var prop in table) {
            if (prop !== 'created_at' && prop !== 'updated_at') {
                $scope.columns.push(prop);
            }
        }
    }

    CreateColumns();

    //this function will re run when the filter function is invoked, in order to repopulate the table
    function CreateRows() {
        var alias;
        $scope.instanceArray = [];
        joinTable.forEach(function (row) {
            var rowValues = [];
            for (var prop in row) {
                if (prop !== 'created_at' && prop !== 'updated_at') rowValues.push(row[prop]);
            }
            $scope.instanceArray.push(rowValues);
        });
    }

    // Sort the values in singleTable so that all the values for a given row are grouped
    CreateRows();
});
app.controller('SingleTableCtrl', function ($scope, TableFactory, $stateParams, singleTable, $window, $state, $uibModal, associations, $log) {

    ///////////////////////////////Putting stuff on scope/////////////////////////////////////////////////

    $scope.theDbName = $stateParams.dbName;
    $scope.theTableName = $stateParams.tableName;
    $scope.singleTable = singleTable[0];
    $scope.selectedAll = false;
    $scope.associations = associations;

    function foreignColumnObj() {
        var foreignCols = {};
        $scope.associations.forEach(function (row) {
            if (row.Table1 === $scope.theTableName && row.Relationship1 === 'hasOne') {
                foreignCols[row.Alias1] = row.Table2;
            } else if (row.Table2 === $scope.theTableName && row.Relationship2 === 'hasOne') {
                foreignCols[row.Alias2] = row.Table1;
            }
        });
        $scope.foreignCols = foreignCols;
    }

    foreignColumnObj();

    $scope.currentTable = $stateParams;

    $scope.myIndex = 1;

    $scope.ids = $scope.singleTable.map(function (row) {
        return row.id;
    });

    //delete a row
    $scope.showDelete = false;
    $scope.toggleDelete = function () {
        $scope.showDelete = !$scope.showDelete;
    };

    $scope.deleteSelected = function (db, table, instanceArray) {
        instanceArray.forEach(function (row) {
            if (row.selected) {
                TableFactory.removeRow(db, table, row['values'][0]['value']).then(function (result) {
                    $scope.singleTable = result;
                    CreateRows();
                });
            }
        });
        $scope.showDelete = false;
    };

    $scope.selectAll = function (instanceArray) {
        if ($scope.selectedAll) {
            instanceArray.forEach(function (row) {
                row.selected = true;
            });
        } else {
            instanceArray.forEach(function (row) {
                row.selected = false;
            });
        }
    };

    $scope.uncheckSelectAll = function (instanceArray) {
        if ($scope.selectedAll === true) {
            $scope.selectedAll = false;
        }
    };

    $scope.removeRow = function (db, table, row) {
        TableFactory.removeRow(db, table, row).then(function (result) {
            $scope.singleTable = result;
            CreateRows();
        });
    };

    $scope.removeColumn = function (db, table, columnName) {
        TableFactory.removeColumn(db, table, columnName).then(function (result) {
            $scope.singleTable = result;
            CreateRows();
            CreateColumns();
        });
    };

    $scope.newRow = function (db, table, arr) {
        var allIds = [];
        arr.forEach(function (rowData) {
            allIds.push(rowData.values[0].value);
        });
        var sorted = allIds.sort(function (a, b) {
            return b - a;
        });
        if (sorted.length > 0) {
            TableFactory.addRow(db, table, sorted[0] + 1).then(function (result) {
                $scope.singleTable = result;
                CreateRows();
            });
        } else {
            TableFactory.addRow(db, table, 1).then(function (result) {
                $scope.singleTable = result;
                CreateRows();
            });
        }
    };

    $scope.addColumn = function (db, table) {
        var colNums = $scope.columns.join(' ').match(/\d+/g);
        if (colNums) {
            var sortedNums = colNums.sort(function (a, b) {
                return b - a;
            });
            var numInNew = Number(sortedNums[0]) + 1;
            var nameNewCol = 'Column ' + numInNew.toString();

            TableFactory.addColumn(db, table, nameNewCol).then(function () {
                return TableFactory.getSingleTable($stateParams.dbName, $stateParams.tableName);
            }).then(function (theTable) {
                $scope.singleTable = theTable[0];
                CreateColumns();
                CreateRows();
            });
        } else {
            var nextColNum = $scope.columns.length + 1;
            var newColName = 'Column ' + nextColNum;
            TableFactory.addColumn(db, table, 'Column 1').then(function () {
                return TableFactory.getSingleTable($stateParams.dbName, $stateParams.tableName);
            }).then(function (theTable) {
                $scope.singleTable = theTable[0];
                CreateColumns();
                CreateRows();
            });
        }
    };

    ///////////////////////////////Organizing stuff into arrays/////////////////////////////////////////////////

    // Get all of the columns to create the columns on the bootstrap table

    function CreateColumns() {
        $scope.columns = [];
        $scope.originalColVals = [];
        var table = $scope.singleTable[0];

        for (var prop in table) {
            if (prop !== 'created_at' && prop !== 'updated_at') {
                $scope.columns.push(prop);
                $scope.originalColVals.push(prop);
            }
        }
    }

    CreateColumns();

    function createVirtualColumns() {
        if ($scope.associations.length > 0) {
            $scope.virtualColumns = [];
            $scope.associations.forEach(function (row) {
                if (row.Table1 === $scope.theTableName && row.Relationship1 === 'hasMany') {
                    var virtual = {};
                    virtual.name = row.Alias1;
                    if (row.Through) {
                        virtual.table = row.Through;
                        virtual.columnkey = row.Alias1;
                    } else {
                        virtual.table = row.Table2;
                        virtual.columnkey = row.Alias2;
                    }
                    $scope.virtualColumns.push(virtual);
                } else if (row.Table2 === $scope.theTableName && row.Relationship2 === 'hasMany') {
                    var virtual = {};
                    virtual.name = row.Alias2;
                    if (row.Through) {
                        virtual.table = row.Through;
                        virtual.columnkey = row.Alias2;
                    } else {
                        virtual.table = row.Table1;
                        virtual.columnkey = row.Alias1;
                    }
                    $scope.virtualColumns.push(virtual);
                }
            });
        }
    }

    createVirtualColumns();

    //this function will re run when the filter function is invoked, in order to repopulate the table
    function CreateRows() {
        $scope.instanceArray = [];
        $scope.singleTable.forEach(function (row) {
            var rowValues = [];
            var rowObj = {};

            for (var prop in row) {
                if (prop !== 'created_at' && prop !== 'updated_at') rowValues.push({
                    col: prop,
                    value: row[prop]
                });
            }
            rowObj.values = rowValues;
            $scope.instanceArray.push(rowObj);
        });
    }

    // Sort the values in singleTable so that all the values for a given row are grouped
    CreateRows();
    //sends the filtering query and then re renders the table with filtered data
    $scope.filter = function (dbName, tableName, data) {
        TableFactory.filter(dbName, tableName, data).then(function (result) {
            $scope.singleTable = result.data;
            CreateRows();
        });
    };

    $scope.checkForeign = function (col) {
        return $scope.foreignCols.hasOwnProperty(col);
    };

    $scope.findPrimary = TableFactory.findPrimary;

    //************ Important *********
    // Make sure to update the row values BEFORE the column name
    // The rowValsToUpdate array stores the values of the ORIGINAL column names so if the column name is updated after the row value, we still have reference to which column the row value references

    ///////////////////////////////Updating Column Stuff/////////////////////////////////////////////////

    $scope.colValsToUpdate = [];

    $scope.updateColumns = function (old, newColName, i) {
        $scope.columns[i] = newColName;

        var colObj = { oldVal: $scope.originalColVals[i], newVal: newColName };

        // if there is nothing in the array to update, push the update into it
        if ($scope.colValsToUpdate.length === 0) {
            $scope.colValsToUpdate.push(colObj);
        } else {
            for (var e = 0; e < $scope.colValsToUpdate.length; e++) {
                if ($scope.colValsToUpdate[e].oldVal === colObj.oldVal) {
                    $scope.colValsToUpdate[e] = colObj;
                    return;
                }
            }
            $scope.colValsToUpdate.push(colObj);
        }
        // check to see if the row is already scheduled to be updated, if it is, then update it with the new thing to be updated
    };

    ///////////////////////////////Updating Row Stuff/////////////////////////////////////////////////

    $scope.rowValsToUpdate = [];

    $scope.updateRow = function (old, newCell, row, i, j) {
        row[i] = newCell;
        var rowObj = {};
        var cols = $scope.originalColVals;
        for (var c = 0; c < cols.length; c++) {
            var colName = cols[j];
            if (row[c] !== undefined) rowObj[colName] = row[c];
            rowObj['id'] = i;
        }

        // if there is nothing in the array to update, push the update into it
        if ($scope.rowValsToUpdate.length === 0) $scope.rowValsToUpdate.push(rowObj);else {
            // check to see if the row is already scheduled to be updated, if it is, then update it with the new thing to be updated
            for (var e = 0; e < $scope.rowValsToUpdate.length; e++) {
                if ($scope.rowValsToUpdate[e].id === rowObj['id']) {
                    $scope.rowValsToUpdate[e] = rowObj;
                    return;
                }
            }
            $scope.rowValsToUpdate.push(rowObj);
        }
    };

    $scope.updateBackend = function () {
        var data = { rows: $scope.rowValsToUpdate, columns: $scope.colValsToUpdate };
        TableFactory.updateBackend($scope.theDbName, $scope.theTableName, data);
    };

    $scope.deleteTable = function () {
        TableFactory.deleteTable($scope.currentTable).then(function () {
            $state.go('Table', { dbName: $scope.theDbName }, { reload: true });
        });
    };

    ///////////////////////////////Querying Stuff/////////////////////////////////////////////////

    $scope.currentTableAssociations = [];

    $scope.tablesToQuery = [];

    associations.forEach(function (row) {
        if (row.Table1 === $scope.theTableName && $scope.currentTableAssociations.indexOf(row.Table2) == -1) {
            $scope.currentTableAssociations.push(row.Table2);
        } else if (row.Table2 === $scope.theTableName && $scope.currentTableAssociations.indexOf(row.Table1) == -1) {
            $scope.currentTableAssociations.push(row.Table1);
        }
    });

    $scope.getAssociated = function (val) {
        if ($scope.tablesToQuery.indexOf($scope.currentTableAssociations[val]) === -1) {
            $scope.tablesToQuery.push($scope.currentTableAssociations[val]);
        } else {
            var i = $scope.tablesToQuery.indexOf($scope.currentTableAssociations[val]);
            $scope.tablesToQuery.splice(i, 1);
        }
    };

    $scope.columnsForQuery = [];

    $scope.getColumnsForTable = function () {
        var promisesForColumns = [];
        $scope.tablesToQuery.forEach(function (tableName) {
            return promisesForColumns.push(TableFactory.getColumnsForTable($scope.theDbName, tableName));
        });
        Promise.all(promisesForColumns).then(function (columns) {
            columns.forEach(function (column) {
                $scope.columnsForQuery.push(column);
                $scope.$evalAsync();
            });
        });
    };

    var selectedColumns = {};
    var queryTable;

    $scope.getDataFromColumns = function (val) {
        if (!selectedColumns) selectedColumns = [];

        var columnName = $scope.columnsForQuery[0]['columns'][val.i];
        var tableName = val.tableName;
        queryTable = tableName;

        if (!selectedColumns[tableName]) selectedColumns[tableName] = [];
        if (selectedColumns[tableName].indexOf(columnName) !== -1) {
            selectedColumns[tableName].splice(selectedColumns[tableName].indexOf(columnName), 1);
        } else {
            selectedColumns[tableName].push(columnName);
        }
        $scope.selectedColumns = selectedColumns;
    };

    // Running the query + rendering the query
    $scope.resultOfQuery = [];

    $scope.queryResult;

    $scope.arr = [];

    // theTableName

    $scope.runJoin = function () {
        // dbName, table1, arrayOfTables, selectedColumns, associations
        var columnsToReturn = $scope.columns.map(function (colName) {
            return $scope.theTableName + '.' + colName;
        });
        for (var prop in $scope.selectedColumns) {
            $scope.selectedColumns[prop].forEach(function (col) {
                columnsToReturn.push(prop + '.' + col);
            });
        }
        TableFactory.runJoin($scope.theDbName, $scope.theTableName, $scope.tablesToQuery, $scope.selectedColumns, $scope.associations, columnsToReturn).then(function (queryResult) {
            $scope.queryResult = queryResult;
        }).then(function () {
            $state.go('Table.Single.query');
        });
    };

    $scope.animationsEnabled = true;

    $scope.open = function (dbName, tblName, col, index) {

        var modalInstance = $uibModal.open({
            animation: $scope.animationsEnabled,
            templateUrl: 'js/table/association.modal.html',
            controller: 'AssociationInstanceCtrl',
            resolve: {
                foreignCols: function foreignCols() {
                    return $scope.foreignCols;
                },
                forTable: function forTable(TableFactory) {
                    console.log(tblName);
                    return TableFactory.findPrimary(dbName, tblName);
                },
                forTableName: function forTableName() {
                    return tblName;
                },
                currTable: function currTable() {
                    return $scope.theTableName;
                },
                colName: function colName() {
                    return col;
                },
                id1: function id1() {
                    return index;
                }
            }
        });

        modalInstance.result.then(function () {
            console.log("CLOSED");
            $scope.$evalAsync();
        });
    };

    $scope.toggleAnimation = function () {
        $scope.animationsEnabled = !$scope.animationsEnabled;
    };
});

app.controller('TableCtrl', function ($scope, allTables, $state, TableFactory, $stateParams, $uibModal, HomeFactory, associations, allColumns) {

    $scope.allTables = allTables;

    $scope.columnArray = [];

    $scope.dbName = $stateParams.dbName;

    $scope.associations = associations;

    $scope.allColumns = allColumns;

    $scope.associationTable = $stateParams.dbName + '_assoc';

    $scope.numTables = $scope.allTables.rows.length;

    $scope.add = function () {
        $scope.columnArray.push('1');
    };

    $scope.$state = $state; // used to hide the list of all tables when in single table state

    $scope.associationTypes = ['hasOne', 'hasMany'];

    $scope.dbName = $stateParams.dbName;

    $scope.makeAssociations = TableFactory.makeAssociations;

    $scope.wherebetween = function (condition) {
        if (condition === "WHERE BETWEEN" || condition === "WHERE NOT BETWEEN") return true;
    };

    $scope.createTable = function (table) {
        TableFactory.createTable(table).then(function () {
            $state.go('Table', { dbName: $scope.dbName });
        });
    };

    $scope.columnDataType = function () {
        $scope.allColumns.forEach(function (obj) {
            if (obj.table_name === $scope.query.table1 && obj.column_name === $scope.query.column) $scope.type = obj.data_type;
        });
    };

    $scope.selectedAssoc = {};

    // $scope.getAssociated = function(tableName) {
    // 	$scope.associations.forEach(function(row){
    // 		if(!$scope.selectedAssoc[tableName]){
    // 			$scope.selectedAssoc[tableName] = [];
    // 		}
    // 		if(row.Table1 === tableName && $scope.selectedAssoc[tableName].indexOf(row.Table2) == -1){
    // 			$scope.selectedAssoc[tableName].push(row.Table2);
    // 		}
    // 		else if(row.Table2 === tableName && $scope.selectedAssoc[tableName].indexOf(row.Table1) == -1){
    // 			$scope.selectedAssoc[tableName].push(row.Table1);	
    // 		}
    // 	})
    // }

    // $scope.currentTableAssociations = [];

    // associations.forEach(function(row){
    // 	if(row.Table1 === tableName && $scope.selectedAssoc[tableName].indexOf(row.Table2) == -1){
    // 		$scope.currentTableAssociations.push(row.Table2);
    // 	}
    // 	else if(row.Table2 === tableName && $scope.selectedAssoc[tableName].indexOf(row.Table1) == -1){
    // 		$scope.selectedAssoc[tableName].push(row.Table1);	
    // 	}
    // })

    $scope.submitQuery = TableFactory.submitQuery;
});

app.factory('TableFactory', function ($http, $stateParams) {

    var TableFactory = {};

    function resToData(res) {
        return res.data;
    }

    TableFactory.getAllTables = function (dbName) {
        return $http.get('/api/clientdb/' + dbName).then(resToData);
    };

    TableFactory.getSingleTable = function (dbName, tableName) {
        return $http.get('/api/clientdb/' + dbName + '/' + tableName).then(resToData);
    };

    TableFactory.getDbName = function (dbName) {
        return $http.get('/api/masterdb/' + dbName).then(resToData);
    };

    TableFactory.filter = function (dbName, tableName, data) {
        return $http.put('/api/clientdb/' + dbName + '/' + tableName + '/filter', data);
    };

    TableFactory.updateBackend = function (dbName, tableName, data) {
        return $http.put('api/clientdb/' + dbName + '/' + tableName, data).then(resToData);
    };

    TableFactory.addRow = function (dbName, tableName, rowNumber) {
        return $http.post('api/clientdb/addrow/' + dbName + '/' + tableName, { rowNumber: rowNumber }).then(resToData);
    };

    TableFactory.removeRow = function (dbName, tableName, rowId) {
        return $http.delete('/api/clientdb/' + dbName + '/' + tableName + '/' + rowId).then(resToData);
    };

    TableFactory.removeColumn = function (dbName, tableName, columnName) {
        return $http.delete('/api/clientdb/' + dbName + '/' + tableName + '/column/' + columnName).then(resToData);
    };

    TableFactory.addColumn = function (dbName, tableName, numNewCol) {
        return $http.post('api/clientdb/addcolumn/' + dbName + '/' + tableName + '/' + numNewCol);
    };
    TableFactory.createTable = function (table) {
        table.dbName = $stateParams.dbName;
        return $http.post('/api/clientdb', table).then(resToData);
    };

    TableFactory.deleteTable = function (currentTable) {
        return $http.delete('/api/clientdb/' + currentTable.dbName + '/' + currentTable.tableName);
    };

    TableFactory.makeAssociations = function (association, dbName) {
        return $http.post('/api/clientdb/' + dbName + '/association', association).then(resToData);
    };

    TableFactory.deleteDb = function (dbName) {
        return $http.delete('/api/clientdb/' + dbName).then(resToData);
    };

    TableFactory.getAssociations = function (dbName, tableName) {
        return $http.get('/api/clientdb/associationtable/' + dbName + '/' + tableName).then(resToData);
    };

    TableFactory.getAllAssociations = function (dbName) {
        return $http.get('/api/clientdb/allassociations/' + dbName).then(resToData);
    };

    TableFactory.getAllColumns = function (dbName) {
        return $http.get('/api/clientdb/getallcolumns/' + dbName).then(resToData);
    };

    TableFactory.getColumnsForTable = function (dbName, tableName) {
        return $http.get('/api/clientdb/columnsfortable/' + dbName + '/' + tableName).then(resToData);
    };

    TableFactory.runJoin = function (dbName, table1, arrayOfTables, selectedColumns, associations, colsToReturn) {
        var data = {};
        data.dbName = dbName;
        data.table2 = arrayOfTables[0];
        data.arrayOfTables = arrayOfTables;
        data.selectedColumns = selectedColumns;
        data.colsToReturn = colsToReturn;

        // [hasMany, hasOne, hasMany primary key, hasOne forgein key]

        associations.forEach(function (row) {
            if (row.Table1 === table1 && row.Table2 === data.table2) {
                data.alias = row.Alias1;
                if (row.Relationship1 === 'hasOne') {
                    data.table1 = row.Table2;
                    data.table2 = row.Table1;
                } else {
                    data.table1 = row.Table1;
                    data.table2 = row.Table2;
                }
            } else if (row.Table1 === data.table2 && row.Table2 === table1) {
                data.alias = row.Alias1;
                if (row.Relationship1 === 'hasMany') {
                    data.table1 = row.Table1;
                    data.table2 = row.Table2;
                } else {
                    data.table1 = row.Table2;
                    data.table2 = row.Table1;
                }
            }
        });

        return $http.put('/api/clientdb/runjoin', data).then(resToData);
    };

    TableFactory.getPrimaryKeys = function (id, dbName, tableName, columnkey) {
        return $http.get('/api/clientdb/' + dbName + '/' + tableName + '/' + id + "/" + columnkey).then(resToData);
    };

    TableFactory.findPrimary = function (dbName, tblName) {
        return $http.get('/api/clientdb/primary/' + dbName + '/' + tblName).then(resToData);
    };

    TableFactory.setForeignKey = function (dbName, tblName, colName, id1, id2) {
        var data = {};
        data.dbName = dbName;
        data.tblName = tblName;
        data.colName = colName;
        data.id1 = id1;
        data.id2 = id2;

        return $http.put('/api/clientdb/setForeignKey', data).then(resToData);
    };

    return TableFactory;
});
app.config(function ($stateProvider) {
    $stateProvider.state('Table', {
        url: '/:dbName',
        templateUrl: 'js/table/table.html',
        controller: 'TableCtrl',
        resolve: {
            allTables: function allTables(TableFactory, $stateParams) {
                return TableFactory.getAllTables($stateParams.dbName);
            },
            associations: function associations(TableFactory, $stateParams) {
                return TableFactory.getAllAssociations($stateParams.dbName);
            },
            allColumns: function allColumns(TableFactory, $stateParams) {
                return TableFactory.getAllColumns($stateParams.dbName);
            }
        }
    });

    $stateProvider.state('Table.Single', {
        url: '/:tableName',
        templateUrl: 'js/table/singletable.html',
        controller: 'SingleTableCtrl',
        resolve: {
            singleTable: function singleTable(TableFactory, $stateParams) {
                return TableFactory.getSingleTable($stateParams.dbName, $stateParams.tableName);
            },
            associations: function associations(TableFactory, $stateParams) {
                return TableFactory.getAssociations($stateParams.dbName, $stateParams.tableName);
            }
        }
    });

    $stateProvider.state('Table.Join', {
        url: '/:tableName/:rowId/:key/join',
        templateUrl: 'js/table/join.html',
        controller: 'JoinTableCtrl',
        resolve: {
            joinTable: function joinTable(TableFactory, $stateParams) {
                return TableFactory.getPrimaryKeys($stateParams.rowId, $stateParams.dbName, $stateParams.tableName, $stateParams.key);
            }
        }
    });

    $stateProvider.state('Table.create', {
        url: '/createtable',
        templateUrl: 'js/table/createtable.html',
        controller: 'TableCtrl'
    });

    $stateProvider.state('Table.setAssociation', {
        url: '/setassociation',
        templateUrl: 'js/table/setassociation.html',
        controller: 'TableCtrl'
    });

    $stateProvider.state('Table.Single.query', {
        url: '/queryresult',
        templateUrl: 'js/table/query.html',
        controller: 'SingleTableCtrl'
    });
});
app.factory('FullstackPics', function () {
    return ['https://pbs.twimg.com/media/B7gBXulCAAAXQcE.jpg:large', 'https://fbcdn-sphotos-c-a.akamaihd.net/hphotos-ak-xap1/t31.0-8/10862451_10205622990359241_8027168843312841137_o.jpg', 'https://pbs.twimg.com/media/B-LKUshIgAEy9SK.jpg', 'https://pbs.twimg.com/media/B79-X7oCMAAkw7y.jpg', 'https://pbs.twimg.com/media/B-Uj9COIIAIFAh0.jpg:large', 'https://pbs.twimg.com/media/B6yIyFiCEAAql12.jpg:large', 'https://pbs.twimg.com/media/CE-T75lWAAAmqqJ.jpg:large', 'https://pbs.twimg.com/media/CEvZAg-VAAAk932.jpg:large', 'https://pbs.twimg.com/media/CEgNMeOXIAIfDhK.jpg:large', 'https://pbs.twimg.com/media/CEQyIDNWgAAu60B.jpg:large', 'https://pbs.twimg.com/media/CCF3T5QW8AE2lGJ.jpg:large', 'https://pbs.twimg.com/media/CAeVw5SWoAAALsj.jpg:large', 'https://pbs.twimg.com/media/CAaJIP7UkAAlIGs.jpg:large', 'https://pbs.twimg.com/media/CAQOw9lWEAAY9Fl.jpg:large', 'https://pbs.twimg.com/media/B-OQbVrCMAANwIM.jpg:large', 'https://pbs.twimg.com/media/B9b_erwCYAAwRcJ.png:large', 'https://pbs.twimg.com/media/B5PTdvnCcAEAl4x.jpg:large', 'https://pbs.twimg.com/media/B4qwC0iCYAAlPGh.jpg:large', 'https://pbs.twimg.com/media/B2b33vRIUAA9o1D.jpg:large', 'https://pbs.twimg.com/media/BwpIwr1IUAAvO2_.jpg:large', 'https://pbs.twimg.com/media/BsSseANCYAEOhLw.jpg:large', 'https://pbs.twimg.com/media/CJ4vLfuUwAAda4L.jpg:large', 'https://pbs.twimg.com/media/CI7wzjEVEAAOPpS.jpg:large', 'https://pbs.twimg.com/media/CIdHvT2UsAAnnHV.jpg:large', 'https://pbs.twimg.com/media/CGCiP_YWYAAo75V.jpg:large', 'https://pbs.twimg.com/media/CIS4JPIWIAI37qu.jpg:large'];
});

app.factory('RandomGreetings', function () {

    var getRandomFromArray = function getRandomFromArray(arr) {
        return arr[Math.floor(Math.random() * arr.length)];
    };

    var greetings = ['Hello, world!', 'At long last, I live!', 'Hello, simple human.', 'What a beautiful day!', 'I\'m like any other project, except that I am yours. :)', 'This empty string is for Lindsay Levine.', 'こんにちは、ユーザー様。', 'Welcome. To. WEBSITE.', ':D', 'Yes, I think we\'ve met before.', 'Gimme 3 mins... I just grabbed this really dope frittata', 'If Cooper could offer only one piece of advice, it would be to nevSQUIRREL!'];

    return {
        greetings: greetings,
        getRandomGreeting: function getRandomGreeting() {
            return getRandomFromArray(greetings);
        }
    };
});

app.directive('fullstackLogo', function () {
    return {
        restrict: 'E',
        templateUrl: 'js/common/directives/fullstack-logo/fullstack-logo.html'
    };
});
app.directive('sidebar', function ($rootScope, AuthService, AUTH_EVENTS, $state) {

    return {
        restrict: 'E',
        scope: {},
        templateUrl: 'js/common/directives/navbar/navbar.html',
        link: function link(scope) {

            scope.items = [{ label: 'Home', state: 'home' }, { label: 'About', state: 'about' }, { label: 'Documentation', state: 'docs' }, { label: 'Members Only', state: 'membersOnly', auth: true }];

            scope.user = null;

            scope.isLoggedIn = function () {
                return AuthService.isAuthenticated();
            };

            scope.logout = function () {
                AuthService.logout().then(function () {
                    $state.go('landingPage');
                });
            };

            var setUser = function setUser() {
                AuthService.getLoggedInUser().then(function (user) {
                    scope.user = user;
                });
            };

            var removeUser = function removeUser() {
                scope.user = null;
            };

            setUser();

            $rootScope.$on(AUTH_EVENTS.loginSuccess, setUser);
            $rootScope.$on(AUTH_EVENTS.logoutSuccess, removeUser);
            $rootScope.$on(AUTH_EVENTS.sessionTimeout, removeUser);
        }

    };
});

app.directive('randoGreeting', function (RandomGreetings) {

    return {
        restrict: 'E',
        templateUrl: 'js/common/directives/rando-greeting/rando-greeting.html',
        link: function link(scope) {
            scope.greeting = RandomGreetings.getRandomGreeting();
        }
    };
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcC5qcyIsImFib3V0L2Fib3V0LmpzIiwiY3JlYXRlREIvY3JlYXRlREIuY29udHJvbGxlci5qcyIsImNyZWF0ZURCL2NyZWF0ZURCLmZhY3RvcnkuanMiLCJjcmVhdGVEQi9jcmVhdGVEQi5zdGF0ZS5qcyIsImRvY3MvZG9jcy5qcyIsImZzYS9mc2EtcHJlLWJ1aWx0LmpzIiwiaG9tZS9ob21lLmNvbnRyb2xsZXIuanMiLCJob21lL2hvbWUuZmFjdG9yeS5qcyIsImhvbWUvaG9tZS5zdGF0ZS5qcyIsImxhbmRpbmdQYWdlL2xhbmRpbmdQYWdlLnN0YXRlLmpzIiwibG9naW4vbG9naW4uanMiLCJtZW1iZXJzLW9ubHkvbWVtYmVycy1vbmx5LmpzIiwib2F1dGgvb2F1dGgtYnV0dG9uLmRpcmVjdGl2ZS5qcyIsInNpZ251cC9zaWdudXAuanMiLCJ0YWJsZS9hc3NvY2lhdGlvbi5jb250cm9sbGVyLmpzIiwidGFibGUvZGVsZXRlREJNb2RhbC5qcyIsInRhYmxlL2RlbGV0ZVRhYmxlTW9kYWwuanMiLCJ0YWJsZS9qb2luLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS9xdWVyeS5jb250cm9sbGVyLmpzIiwidGFibGUvc2luZ2xldGFibGUuY29udHJvbGxlci5qcyIsInRhYmxlL3RhYmxlLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS90YWJsZS5mYWN0b3J5LmpzIiwidGFibGUvdGFibGUuc3RhdGUuanMiLCJjb21tb24vZmFjdG9yaWVzL0Z1bGxzdGFja1BpY3MuanMiLCJjb21tb24vZmFjdG9yaWVzL1JhbmRvbUdyZWV0aW5ncy5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL2Z1bGxzdGFjay1sb2dvL2Z1bGxzdGFjay1sb2dvLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvbmF2YmFyL25hdmJhci5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL3JhbmRvLWdyZWV0aW5nL3JhbmRvLWdyZWV0aW5nLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOztBQUNBLE9BQUEsR0FBQSxHQUFBLFFBQUEsTUFBQSxDQUFBLHVCQUFBLEVBQUEsQ0FBQSxhQUFBLEVBQUEsV0FBQSxFQUFBLGNBQUEsRUFBQSxXQUFBLENBQUEsQ0FBQTs7QUFFQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGtCQUFBLEVBQUEsaUJBQUEsRUFBQTs7QUFFQSxzQkFBQSxTQUFBLENBQUEsSUFBQTs7QUFFQSx1QkFBQSxTQUFBLENBQUEsR0FBQTs7QUFFQSx1QkFBQSxJQUFBLENBQUEsaUJBQUEsRUFBQSxZQUFBO0FBQ0EsZUFBQSxRQUFBLENBQUEsTUFBQTtBQUNBLEtBRkE7QUFHQSxDQVRBOzs7QUFZQSxJQUFBLEdBQUEsQ0FBQSxVQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUEsTUFBQSxFQUFBOzs7QUFHQSxRQUFBLCtCQUFBLFNBQUEsNEJBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxJQUFBLE1BQUEsSUFBQSxDQUFBLFlBQUE7QUFDQSxLQUZBOzs7O0FBTUEsZUFBQSxHQUFBLENBQUEsbUJBQUEsRUFBQSxVQUFBLEtBQUEsRUFBQSxPQUFBLEVBQUEsUUFBQSxFQUFBOztBQUVBLFlBQUEsQ0FBQSw2QkFBQSxPQUFBLENBQUEsRUFBQTs7O0FBR0E7QUFDQTs7QUFFQSxZQUFBLFlBQUEsZUFBQSxFQUFBLEVBQUE7OztBQUdBO0FBQ0E7OztBQUdBLGNBQUEsY0FBQTs7QUFFQSxvQkFBQSxlQUFBLEdBQUEsSUFBQSxDQUFBLFVBQUEsSUFBQSxFQUFBOzs7O0FBSUEsZ0JBQUEsSUFBQSxFQUFBO0FBQ0EsdUJBQUEsRUFBQSxDQUFBLFFBQUEsSUFBQSxFQUFBLFFBQUE7QUFDQSxhQUZBLE1BRUE7QUFDQSx1QkFBQSxFQUFBLENBQUEsT0FBQTtBQUNBO0FBQ0EsU0FUQTtBQVdBLEtBNUJBO0FBOEJBLENBdkNBOztBQ2ZBLElBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBOzs7QUFHQSxtQkFBQSxLQUFBLENBQUEsT0FBQSxFQUFBO0FBQ0EsYUFBQSxRQURBO0FBRUEsb0JBQUEsaUJBRkE7QUFHQSxx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LElBQUEsRUFBQTtBQUNBLHVCQUFBLEdBQUEsSUFBQSxDQUFBLFFBQUEsSUFBQSxDQUFBO0FBQ0E7Ozs7O0FBS0EsbUJBQUEsTUFBQSxHQUFBLENBQUEsVUFBQSxFQUFBLElBQUEsQ0FBQSxpQkFBQSxFQUFBLEtBQUEsQ0FBQSxZQUFBO0FBQ0EsdUJBQUEsSUFBQTtBQUNBLGFBRkEsQ0FBQTtBQUlBLFNBckJBOztBQXVCQSxhQUFBLE1BQUEsR0FBQSxVQUFBLFdBQUEsRUFBQTtBQUNBLG1CQUFBLE1BQUEsSUFBQSxDQUFBLFNBQUEsRUFBQSxXQUFBLEVBQ0EsSUFEQSxDQUNBLGlCQURBLEVBRUEsS0FGQSxDQUVBLFlBQUE7QUFDQSx1QkFBQSxHQUFBLE1BQUEsQ0FBQSxFQUFBLFNBQUEsNkJBQUEsRUFBQSxDQUFBO0FBQ0EsYUFKQSxDQUFBO0FBS0EsU0FOQTs7QUFRQSxhQUFBLEtBQUEsR0FBQSxVQUFBLFdBQUEsRUFBQTtBQUNBLG1CQUFBLE1BQUEsSUFBQSxDQUFBLFFBQUEsRUFBQSxXQUFBLEVBQ0EsSUFEQSxDQUNBLGlCQURBLEVBRUEsS0FGQSxDQUVBLFlBQUE7QUFDQSx1QkFBQSxHQUFBLE1BQUEsQ0FBQSxFQUFBLFNBQUEsNEJBQUEsRUFBQSxDQUFBO0FBQ0EsYUFKQSxDQUFBO0FBS0EsU0FOQTs7QUFRQSxhQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsbUJBQUEsTUFBQSxHQUFBLENBQUEsU0FBQSxFQUFBLElBQUEsQ0FBQSxZQUFBO0FBQ0Esd0JBQUEsT0FBQTtBQUNBLDJCQUFBLFVBQUEsQ0FBQSxZQUFBLGFBQUE7QUFDQSxhQUhBLENBQUE7QUFJQSxTQUxBO0FBT0EsS0E3REE7O0FBK0RBLFFBQUEsT0FBQSxDQUFBLFNBQUEsRUFBQSxVQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUE7O0FBRUEsWUFBQSxPQUFBLElBQUE7O0FBRUEsbUJBQUEsR0FBQSxDQUFBLFlBQUEsZ0JBQUEsRUFBQSxZQUFBO0FBQ0EsaUJBQUEsT0FBQTtBQUNBLFNBRkE7O0FBSUEsbUJBQUEsR0FBQSxDQUFBLFlBQUEsY0FBQSxFQUFBLFlBQUE7QUFDQSxpQkFBQSxPQUFBO0FBQ0EsU0FGQTs7QUFJQSxhQUFBLEVBQUEsR0FBQSxJQUFBO0FBQ0EsYUFBQSxJQUFBLEdBQUEsSUFBQTs7QUFFQSxhQUFBLE1BQUEsR0FBQSxVQUFBLFNBQUEsRUFBQSxJQUFBLEVBQUE7QUFDQSxpQkFBQSxFQUFBLEdBQUEsU0FBQTtBQUNBLGlCQUFBLElBQUEsR0FBQSxJQUFBO0FBQ0EsU0FIQTs7QUFLQSxhQUFBLE9BQUEsR0FBQSxZQUFBO0FBQ0EsaUJBQUEsRUFBQSxHQUFBLElBQUE7QUFDQSxpQkFBQSxJQUFBLEdBQUEsSUFBQTtBQUNBLFNBSEE7QUFLQSxLQXpCQTtBQTJCQSxDQTVJQTs7QUNBQSxJQUFBLFVBQUEsQ0FBQSxVQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBLE1BQUEsRUFBQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxNQUFBO0FBQ0EsQ0FIQTs7QUNBQSxJQUFBLE9BQUEsQ0FBQSxhQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUE7O0FBRUEsUUFBQSxjQUFBLEVBQUE7O0FBRUEsYUFBQSxTQUFBLENBQUEsR0FBQSxFQUFBO0FBQ0EsZUFBQSxJQUFBLElBQUE7QUFDQTs7QUFFQSxnQkFBQSxTQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsZUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGdCQUFBLFFBQUEsR0FBQSxVQUFBLElBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsSUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLFdBQUEsV0FBQTtBQUNBLENBbkJBO0FDQUEsSUFBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxtQkFBQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsYUFBQSxPQURBO0FBRUEscUJBQUEsbUJBRkE7QUFHQSxvQkFBQSxVQUhBO0FBSUEsaUJBQUE7QUFDQSxvQkFBQSxnQkFBQSxXQUFBLEVBQUE7QUFDQSx1QkFBQSxZQUFBLFNBQUEsRUFBQTtBQUNBLGFBSEE7QUFJQSwwQkFBQSxzQkFBQSxXQUFBLEVBQUE7QUFDQSx1QkFBQSxZQUFBLGVBQUEsRUFBQTtBQUNBO0FBTkE7QUFKQSxLQUFBO0FBYUEsQ0FkQTtBQ0FBLElBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0EsbUJBQUEsS0FBQSxDQUFBLGFBQUEsRUFBQTtBQUNBLGFBQUEsR0FEQTtBQUVBLHFCQUFBO0FBRkEsS0FBQTtBQU1BLENBUEE7QUNBQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTs7QUFFQSxtQkFBQSxLQUFBLENBQUEsT0FBQSxFQUFBO0FBQ0EsYUFBQSxRQURBO0FBRUEscUJBQUEscUJBRkE7QUFHQSxvQkFBQTtBQUhBLEtBQUE7QUFNQSxDQVJBOztBQVVBLElBQUEsVUFBQSxDQUFBLFdBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxXQUFBLEVBQUEsTUFBQSxFQUFBOztBQUVBLFdBQUEsS0FBQSxHQUFBLEVBQUE7QUFDQSxXQUFBLEtBQUEsR0FBQSxJQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLFVBQUEsU0FBQSxFQUFBOztBQUVBLGVBQUEsS0FBQSxHQUFBLElBQUE7O0FBRUEsb0JBQUEsS0FBQSxDQUFBLFNBQUEsRUFBQSxJQUFBLENBQUEsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxNQUFBO0FBQ0EsU0FGQSxFQUVBLEtBRkEsQ0FFQSxZQUFBO0FBQ0EsbUJBQUEsS0FBQSxHQUFBLDRCQUFBO0FBQ0EsU0FKQTtBQU1BLEtBVkE7QUFZQSxDQWpCQTs7QUNWQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTs7QUFFQSxtQkFBQSxLQUFBLENBQUEsYUFBQSxFQUFBO0FBQ0EsYUFBQSxlQURBO0FBRUEsa0JBQUEsbUVBRkE7QUFHQSxvQkFBQSxvQkFBQSxNQUFBLEVBQUEsV0FBQSxFQUFBO0FBQ0Esd0JBQUEsUUFBQSxHQUFBLElBQUEsQ0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLHVCQUFBLEtBQUEsR0FBQSxLQUFBO0FBQ0EsYUFGQTtBQUdBLFNBUEE7OztBQVVBLGNBQUE7QUFDQSwwQkFBQTtBQURBO0FBVkEsS0FBQTtBQWVBLENBakJBOztBQW1CQSxJQUFBLE9BQUEsQ0FBQSxhQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUE7O0FBRUEsUUFBQSxXQUFBLFNBQUEsUUFBQSxHQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSwyQkFBQSxFQUFBLElBQUEsQ0FBQSxVQUFBLFFBQUEsRUFBQTtBQUNBLG1CQUFBLFNBQUEsSUFBQTtBQUNBLFNBRkEsQ0FBQTtBQUdBLEtBSkE7O0FBTUEsV0FBQTtBQUNBLGtCQUFBO0FBREEsS0FBQTtBQUlBLENBWkE7QUNuQkE7O0FBRUEsSUFBQSxTQUFBLENBQUEsYUFBQSxFQUFBLFlBQUE7QUFDQSxXQUFBO0FBQ0EsZUFBQTtBQUNBLDBCQUFBO0FBREEsU0FEQTtBQUlBLGtCQUFBLEdBSkE7QUFLQSxxQkFBQTtBQUxBLEtBQUE7QUFPQSxDQVJBOztBQ0ZBLElBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBOztBQUVBLG1CQUFBLEtBQUEsQ0FBQSxRQUFBLEVBQUE7QUFDQSxhQUFBLFNBREE7QUFFQSxxQkFBQSx1QkFGQTtBQUdBLG9CQUFBO0FBSEEsS0FBQTtBQU1BLENBUkE7O0FBVUEsSUFBQSxVQUFBLENBQUEsWUFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsRUFBQTtBQUNBLFdBQUEsS0FBQSxHQUFBLElBQUE7O0FBRUEsV0FBQSxVQUFBLEdBQUEsVUFBQSxVQUFBLEVBQUE7QUFDQSxlQUFBLEtBQUEsR0FBQSxJQUFBO0FBQ0Esb0JBQUEsTUFBQSxDQUFBLFVBQUEsRUFBQSxJQUFBLENBQUEsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxNQUFBO0FBQ0EsU0FGQSxFQUVBLEtBRkEsQ0FFQSxZQUFBO0FBQ0EsbUJBQUEsS0FBQSxHQUFBLDhDQUFBO0FBQ0EsU0FKQTtBQU1BLEtBUkE7QUFVQSxDQWZBOztBQ1ZBLElBQUEsVUFBQSxDQUFBLHlCQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsaUJBQUEsRUFBQSxXQUFBLEVBQUEsWUFBQSxFQUFBLFdBQUEsRUFBQSxZQUFBLEVBQUEsTUFBQSxFQUFBLFFBQUEsRUFBQSxZQUFBLEVBQUEsU0FBQSxFQUFBLE9BQUEsRUFBQSxHQUFBLEVBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBOztBQUVBLFdBQUEsV0FBQSxHQUFBLFFBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsWUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxTQUFBOztBQUVBLFdBQUEsT0FBQSxHQUFBLE9BQUE7O0FBRUEsV0FBQSxHQUFBLEdBQUEsR0FBQTs7QUFFQSxXQUFBLFdBQUEsR0FBQSxZQUFBOztBQUVBLGVBQUEsT0FBQSxHQUFBLEtBQUEsR0FBQTtBQUNBLGdCQUFBLEdBQUEsQ0FBQSxPQUFBLE9BQUE7QUFDQSxLQUpBOztBQVFBLGFBQUEsYUFBQSxHQUFBO0FBQ0EsZUFBQSxPQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsUUFBQSxTQUFBLENBQUEsQ0FBQTs7QUFHQSxhQUFBLElBQUEsSUFBQSxJQUFBLEtBQUEsRUFBQTtBQUNBLGdCQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxJQUFBO0FBQ0E7QUFDQTtBQUNBOztBQUVBOzs7QUFJQSxhQUFBLFVBQUEsR0FBQTtBQUNBLGVBQUEsYUFBQSxHQUFBLEVBQUE7QUFDQSxpQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxZQUFBLEVBQUE7QUFDQSxpQkFBQSxJQUFBLElBQUEsSUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxTQUFBLFlBQUEsSUFBQSxTQUFBLFlBQUEsRUFBQSxVQUFBLElBQUEsQ0FBQSxJQUFBLElBQUEsQ0FBQTtBQUNBO0FBQ0EsbUJBQUEsYUFBQSxDQUFBLElBQUEsQ0FBQSxTQUFBO0FBQ0EsU0FOQTtBQU9BOzs7QUFHQTs7QUFHQSxXQUFBLGFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxPQUFBLEVBQUEsT0FBQSxFQUFBLEdBQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSwwQkFBQSxLQUFBO0FBQ0EscUJBQUEsYUFBQSxDQUFBLE1BQUEsRUFBQSxPQUFBLEVBQUEsT0FBQSxFQUFBLEdBQUEsRUFBQSxHQUFBLEVBQ0EsSUFEQSxDQUNBLFlBQUE7QUFDQSxtQkFBQSxFQUFBLENBQUEsY0FBQSxFQUFBLEVBQUEsUUFBQSxPQUFBLE1BQUEsRUFBQSxXQUFBLE9BQUEsU0FBQSxFQUFBLEVBQUEsRUFBQSxRQUFBLElBQUEsRUFBQTtBQUNBLFNBSEE7QUFJQSxLQU5BOztBQVVBLFdBQUEsRUFBQSxHQUFBLFlBQUE7QUFDQSwwQkFBQSxLQUFBLENBQUEsT0FBQSxRQUFBLENBQUEsSUFBQTtBQUNBLEtBRkE7O0FBSUEsV0FBQSxNQUFBLEdBQUEsWUFBQTtBQUNBLDBCQUFBLE9BQUEsQ0FBQSxRQUFBO0FBQ0EsS0FGQTtBQUdBLENBdEVBO0FDQUEsSUFBQSxVQUFBLENBQUEsY0FBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxJQUFBLEVBQUE7O0FBRUEsV0FBQSxLQUFBLEdBQUEsQ0FBQSxPQUFBLEVBQUEsT0FBQSxFQUFBLE9BQUEsQ0FBQTs7QUFFQSxXQUFBLGlCQUFBLEdBQUEsSUFBQTs7QUFFQSxXQUFBLElBQUEsR0FBQSxVQUFBLElBQUEsRUFBQTs7QUFFQSxZQUFBLGdCQUFBLFVBQUEsSUFBQSxDQUFBO0FBQ0EsdUJBQUEsT0FBQSxpQkFEQTtBQUVBLHlCQUFBLHNCQUZBO0FBR0Esd0JBQUEsc0JBSEE7QUFJQSxrQkFBQSxJQUpBO0FBS0EscUJBQUE7QUFDQSx1QkFBQSxpQkFBQTtBQUNBLDJCQUFBLE9BQUEsS0FBQTtBQUNBO0FBSEE7QUFMQSxTQUFBLENBQUE7O0FBWUEsc0JBQUEsTUFBQSxDQUFBLElBQUEsQ0FBQSxVQUFBLFlBQUEsRUFBQTtBQUNBLG1CQUFBLFFBQUEsR0FBQSxZQUFBO0FBQ0EsU0FGQSxFQUVBLFlBQUE7QUFDQSxpQkFBQSxJQUFBLENBQUEseUJBQUEsSUFBQSxJQUFBLEVBQUE7QUFDQSxTQUpBO0FBS0EsS0FuQkE7O0FBcUJBLFdBQUEsZUFBQSxHQUFBLFlBQUE7QUFDQSxlQUFBLGlCQUFBLEdBQUEsQ0FBQSxPQUFBLGlCQUFBO0FBQ0EsS0FGQTtBQUlBLENBL0JBOztBQWlDQSxJQUFBLFVBQUEsQ0FBQSxzQkFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLGlCQUFBLEVBQUEsS0FBQSxFQUFBLFlBQUEsRUFBQSxXQUFBLEVBQUEsWUFBQSxFQUFBLE1BQUEsRUFBQTs7QUFHQSxXQUFBLFVBQUEsR0FBQSxlQUFBO0FBQ0EsV0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBOztBQUVBLFdBQUEsV0FBQSxHQUFBLFlBQUE7QUFDQSwwQkFBQSxLQUFBLENBQUEsT0FBQSxRQUFBLENBQUEsSUFBQTtBQUNBLHFCQUFBLFFBQUEsQ0FBQSxPQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsWUFBQTtBQUNBLHdCQUFBLFFBQUEsQ0FBQSxPQUFBLE1BQUE7QUFDQSxTQUhBLEVBSUEsSUFKQSxDQUlBLFlBQUE7QUFDQSxtQkFBQSxFQUFBLENBQUEsTUFBQSxFQUFBLEVBQUEsRUFBQSxFQUFBLFFBQUEsSUFBQSxFQUFBO0FBQ0EsU0FOQTtBQU9BLEtBVEE7O0FBV0EsV0FBQSxLQUFBLEdBQUEsS0FBQTtBQUNBLFdBQUEsUUFBQSxHQUFBO0FBQ0EsY0FBQSxPQUFBLEtBQUEsQ0FBQSxDQUFBO0FBREEsS0FBQTs7QUFJQSxXQUFBLEVBQUEsR0FBQSxZQUFBO0FBQ0EsMEJBQUEsS0FBQSxDQUFBLE9BQUEsUUFBQSxDQUFBLElBQUE7QUFDQSxLQUZBOztBQUlBLFdBQUEsTUFBQSxHQUFBLFlBQUE7QUFDQSwwQkFBQSxPQUFBLENBQUEsUUFBQTtBQUNBLEtBRkE7QUFHQSxDQTdCQTtBQ2pDQSxJQUFBLFVBQUEsQ0FBQSxjQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUE7O0FBRUEsV0FBQSxpQkFBQSxHQUFBLElBQUE7O0FBRUEsV0FBQSxJQUFBLEdBQUEsVUFBQSxJQUFBLEVBQUE7O0FBRUEsWUFBQSxnQkFBQSxVQUFBLElBQUEsQ0FBQTtBQUNBLHVCQUFBLE9BQUEsaUJBREE7QUFFQSx5QkFBQSxzQkFGQTtBQUdBLHdCQUFBLHNCQUhBO0FBSUEsa0JBQUEsSUFKQTtBQUtBLHFCQUFBO0FBQ0EsdUJBQUEsaUJBQUE7QUFDQSwyQkFBQSxPQUFBLEtBQUE7QUFDQTtBQUhBO0FBTEEsU0FBQSxDQUFBOztBQVlBLHNCQUFBLE1BQUEsQ0FBQSxJQUFBLENBQUEsVUFBQSxZQUFBLEVBQUE7QUFDQSxtQkFBQSxRQUFBLEdBQUEsWUFBQTtBQUNBLFNBRkEsRUFFQSxZQUFBO0FBQ0EsaUJBQUEsSUFBQSxDQUFBLHlCQUFBLElBQUEsSUFBQSxFQUFBO0FBQ0EsU0FKQTtBQUtBLEtBbkJBO0FBcUJBLENBekJBOztBQTRCQSxJQUFBLFVBQUEsQ0FBQSxzQkFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLGlCQUFBLEVBQUEsS0FBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBOztBQUVBLFdBQUEsWUFBQSxHQUFBLGVBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsWUFBQTtBQUNBLHFCQUFBLFFBQUEsQ0FBQSxPQUFBLE1BQUE7O0FBRUEsS0FIQTs7QUFLQSxXQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsMEJBQUEsT0FBQSxDQUFBLFFBQUE7QUFDQSxLQUZBO0FBR0EsQ0FkQTtBQzVCQSxJQUFBLFVBQUEsQ0FBQSxlQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQSxTQUFBLEVBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsU0FBQTs7QUFHQSxhQUFBLGFBQUEsR0FBQTtBQUNBLGVBQUEsT0FBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLFFBQUEsT0FBQSxTQUFBLENBQUEsQ0FBQSxDQUFBOztBQUdBLGFBQUEsSUFBQSxJQUFBLElBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxPQUFBLENBQUEsSUFBQSxDQUFBLElBQUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7OztBQUlBLGFBQUEsVUFBQSxHQUFBO0FBQ0EsWUFBQSxLQUFBO0FBQ0EsZUFBQSxhQUFBLEdBQUEsRUFBQTtBQUNBLGtCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLFlBQUEsRUFBQTtBQUNBLGlCQUFBLElBQUEsSUFBQSxJQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBLFVBQUEsSUFBQSxDQUFBLElBQUEsSUFBQSxDQUFBO0FBQ0E7QUFDQSxtQkFBQSxhQUFBLENBQUEsSUFBQSxDQUFBLFNBQUE7QUFDQSxTQU5BO0FBT0E7OztBQUdBO0FBR0EsQ0FyQ0E7QUNBQSxJQUFBLFVBQUEsQ0FBQSxnQkFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUE7O0FBR0EsYUFBQSxhQUFBLEdBQUE7QUFDQSxlQUFBLE9BQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxRQUFBLE9BQUEsU0FBQSxDQUFBLENBQUEsQ0FBQTs7QUFHQSxhQUFBLElBQUEsSUFBQSxJQUFBLEtBQUEsRUFBQTtBQUNBLGdCQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxJQUFBO0FBQ0E7QUFDQTtBQUNBOztBQUVBOzs7QUFJQSxhQUFBLFVBQUEsR0FBQTtBQUNBLFlBQUEsS0FBQTtBQUNBLGVBQUEsYUFBQSxHQUFBLEVBQUE7QUFDQSxrQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxZQUFBLEVBQUE7QUFDQSxpQkFBQSxJQUFBLElBQUEsSUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxTQUFBLFlBQUEsSUFBQSxTQUFBLFlBQUEsRUFBQSxVQUFBLElBQUEsQ0FBQSxJQUFBLElBQUEsQ0FBQTtBQUNBO0FBQ0EsbUJBQUEsYUFBQSxDQUFBLElBQUEsQ0FBQSxTQUFBO0FBQ0EsU0FOQTtBQU9BOzs7QUFHQTtBQUdBLENBbkNBO0FDQUEsSUFBQSxVQUFBLENBQUEsaUJBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBLFdBQUEsRUFBQSxPQUFBLEVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxZQUFBLEVBQUEsSUFBQSxFQUFBOzs7O0FBSUEsV0FBQSxTQUFBLEdBQUEsYUFBQSxNQUFBO0FBQ0EsV0FBQSxZQUFBLEdBQUEsYUFBQSxTQUFBO0FBQ0EsV0FBQSxXQUFBLEdBQUEsWUFBQSxDQUFBLENBQUE7QUFDQSxXQUFBLFdBQUEsR0FBQSxLQUFBO0FBQ0EsV0FBQSxZQUFBLEdBQUEsWUFBQTs7QUFJQSxhQUFBLGdCQUFBLEdBQUE7QUFDQSxZQUFBLGNBQUEsRUFBQTtBQUNBLGVBQUEsWUFBQSxDQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLElBQUEsTUFBQSxLQUFBLE9BQUEsWUFBQSxJQUFBLElBQUEsYUFBQSxLQUFBLFFBQUEsRUFBQTtBQUNBLDRCQUFBLElBQUEsTUFBQSxJQUFBLElBQUEsTUFBQTtBQUNBLGFBRkEsTUFFQSxJQUFBLElBQUEsTUFBQSxLQUFBLE9BQUEsWUFBQSxJQUFBLElBQUEsYUFBQSxLQUFBLFFBQUEsRUFBQTtBQUNBLDRCQUFBLElBQUEsTUFBQSxJQUFBLElBQUEsTUFBQTtBQUNBO0FBQ0EsU0FOQTtBQU9BLGVBQUEsV0FBQSxHQUFBLFdBQUE7QUFDQTs7QUFFQTs7QUFHQSxXQUFBLFlBQUEsR0FBQSxZQUFBOztBQUVBLFdBQUEsT0FBQSxHQUFBLENBQUE7O0FBRUEsV0FBQSxHQUFBLEdBQUEsT0FBQSxXQUFBLENBQUEsR0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZUFBQSxJQUFBLEVBQUE7QUFDQSxLQUZBLENBQUE7OztBQUtBLFdBQUEsVUFBQSxHQUFBLEtBQUE7QUFDQSxXQUFBLFlBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxVQUFBLEdBQUEsQ0FBQSxPQUFBLFVBQUE7QUFDQSxLQUZBOztBQUlBLFdBQUEsY0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxhQUFBLEVBQUE7QUFDQSxzQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxJQUFBLFFBQUEsRUFBQTtBQUNBLDZCQUFBLFNBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLElBQUEsUUFBQSxFQUFBLENBQUEsRUFBQSxPQUFBLENBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSwyQkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsaUJBSkE7QUFLQTtBQUNBLFNBUkE7QUFTQSxlQUFBLFVBQUEsR0FBQSxLQUFBO0FBQ0EsS0FYQTs7QUFhQSxXQUFBLFNBQUEsR0FBQSxVQUFBLGFBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxXQUFBLEVBQUE7QUFDQSwwQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxRQUFBLEdBQUEsSUFBQTtBQUNBLGFBRkE7QUFHQSxTQUpBLE1BSUE7QUFDQSwwQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxRQUFBLEdBQUEsS0FBQTtBQUNBLGFBRkE7QUFHQTtBQUNBLEtBVkE7O0FBWUEsV0FBQSxnQkFBQSxHQUFBLFVBQUEsYUFBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLFdBQUEsS0FBQSxJQUFBLEVBQUE7QUFDQSxtQkFBQSxXQUFBLEdBQUEsS0FBQTtBQUNBO0FBQ0EsS0FKQTs7QUFNQSxXQUFBLFNBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsR0FBQSxFQUFBO0FBQ0EscUJBQUEsU0FBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsR0FBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE1BQUEsRUFBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxNQUFBO0FBQ0E7QUFDQSxTQUpBO0FBS0EsS0FOQTs7QUFRQSxXQUFBLFlBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUFBO0FBQ0EscUJBQUEsWUFBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE1BQUEsRUFBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxNQUFBO0FBQ0E7QUFDQTtBQUNBLFNBTEE7QUFNQSxLQVBBOztBQVNBLFdBQUEsTUFBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLFNBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxDQUFBLFVBQUEsT0FBQSxFQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBLFFBQUEsTUFBQSxDQUFBLENBQUEsRUFBQSxLQUFBO0FBQ0EsU0FGQTtBQUdBLFlBQUEsU0FBQSxPQUFBLElBQUEsQ0FBQSxVQUFBLENBQUEsRUFBQSxDQUFBLEVBQUE7QUFDQSxtQkFBQSxJQUFBLENBQUE7QUFDQSxTQUZBLENBQUE7QUFHQSxZQUFBLE9BQUEsTUFBQSxHQUFBLENBQUEsRUFBQTtBQUNBLHlCQUFBLE1BQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsYUFKQTtBQU1BLFNBUEEsTUFPQTtBQUNBLHlCQUFBLE1BQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLENBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsYUFKQTtBQUtBO0FBQ0EsS0F0QkE7O0FBd0JBLFdBQUEsU0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQTtBQUNBLFlBQUEsVUFBQSxPQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsR0FBQSxFQUFBLEtBQUEsQ0FBQSxNQUFBLENBQUE7QUFDQSxZQUFBLE9BQUEsRUFB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QUE7QUFDQTtBQUNBLGFBeEJBO0FBeUJBO0FBQ0E7O0FBRUE7OztBQUdBLGFBQUEsVUFBQSxHQUFBO0FBQ0EsZUFBQSxhQUFBLEdBQUEsRUFBQTtBQUNBLGVBQUEsV0FBQSxDQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLFlBQUEsRUFBQTtBQUNBLGdCQUFBLFNBQUEsRUFBQTs7QUFFQSxpQkFBQSxJQUFBLElBQUEsSUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxTQUFBLFlBQUEsSUFBQSxTQUFBLFlBQUEsRUFBQSxVQUFBLElBQUEsQ0FBQTtBQUNBLHlCQUFBLElBREE7QUFFQSwyQkFBQSxJQUFBLElBQUE7QUFGQSxpQkFBQTtBQUlBO0FBQ0EsbUJBQUEsTUFBQSxHQUFBLFNBQUE7QUFDQSxtQkFBQSxhQUFBLENBQUEsSUFBQSxDQUFBLE1BQUE7QUFDQSxTQVpBO0FBYUE7OztBQUdBOztBQUVBLFdBQUEsTUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxJQUFBLEVBQUE7QUFDQSxxQkFBQSxNQUFBLENBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxJQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsbUJBQUEsV0FBQSxHQUFBLE9BQUEsSUFBQTtBQUNBO0FBQ0EsU0FKQTtBQUtBLEtBTkE7O0FBU0EsV0FBQSxZQUFBLEdBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLE9BQUEsV0FBQSxDQUFBLGNBQUEsQ0FBQSxHQUFBLENBQUE7QUFDQSxLQUZBOztBQUlBLFdBQUEsV0FBQSxHQUFBLGFBQUEsV0FBQTs7Ozs7Ozs7QUFTQSxXQUFBLGVBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsYUFBQSxHQUFBLFVBQUEsR0FBQSxFQUFBLFVBQUEsRUFBQSxDQUFBLEVBQUE7QUFDQSxlQUFBLE9BQUEsQ0FBQSxDQUFBLElBQUEsVUFBQTs7QUFFQSxZQUFBLFNBQUEsRUFBQSxRQUFBLE9BQUEsZUFBQSxDQUFBLENBQUEsQ0FBQSxFQUFBLFFBQUEsVUFBQSxFQUFBOzs7QUFHQSxZQUFBLE9BQUEsZUFBQSxDQUFBLE1BQUEsS0FBQSxDQUFBLEVBQUE7QUFBQSxtQkFBQSxlQUFBLENBQUEsSUFBQSxDQUFBLE1BQUE7QUFBQSxTQUFBLE1BQUE7QUFDQSxpQkFBQSxJQUFBLElBQUEsQ0FBQSxFQUFBLElBQUEsT0FBQSxlQUFBLENBQUEsTUFBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLE9BQUEsZUFBQSxDQUFBLENBQUEsRUFBQSxNQUFBLEtBQUEsT0FBQSxNQUFBLEVBQUE7QUFDQSwyQkFBQSxlQUFBLENBQUEsQ0FBQSxJQUFBLE1BQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQSxtQkFBQSxlQUFBLENBQUEsSUFBQSxDQUFBLE1BQUE7QUFDQTs7QUFFQSxLQWhCQTs7OztBQW9CQSxXQUFBLGVBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLFVBQUEsR0FBQSxFQUFBLE9BQUEsRUFBQSxHQUFBLEVBQUEsQ0FBQSxFQUFBLENBQUEsRUFBQTtBQUNBLFlBQUEsQ0FBQSxJQUFBLE9BQUE7QUFDQSxZQUFBLFNBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxPQUFBLGVBQUE7QUFDQSxhQUFBLElBQUEsSUFBQSxDQUFBLEVBQUEsSUFBQSxLQUFBLE1BQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxVQUFBLEtBQUEsQ0FBQSxDQUFBO0FBQ0EsZ0JBQUEsSUFBQSxDQUFBLE1BQUEsU0FBQSxFQUFBLE9BQUEsT0FBQSxJQUFBLElBQUEsQ0FBQSxDQUFBO0FBQ0EsbUJBQUEsSUFBQSxJQUFBLENBQUE7QUFDQTs7O0FBR0EsWUFBQSxPQUFBLGVBQUEsQ0FBQSxNQUFBLEtBQUEsQ0FBQSxFQUFBLE9BQUEsZUFBQSxDQUFBLElBQUEsQ0FBQSxNQUFBLEVBQUEsS0FDQTs7QUFFQSxpQkFBQSxJQUFBLElBQUEsQ0FBQSxFQUFBLElBQUEsT0FBQSxlQUFBLENBQUEsTUFBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLE9BQUEsZUFBQSxDQUFBLENBQUEsRUFBQSxFQUFBLEtBQUEsT0FBQSxJQUFBLENBQUEsRUFBQTtBQUNBLDJCQUFBLGVBQUEsQ0FBQSxDQUFBLElBQUEsTUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLG1CQUFBLGVBQUEsQ0FBQSxJQUFBLENBQUEsTUFBQTtBQUNBO0FBQ0EsS0F0QkE7O0FBd0JBLFdBQUEsYUFBQSxHQUFBLFlBQUE7QUFDQSxZQUFBLE9BQUEsRUFBQSxNQUFBLE9BQUEsZUFBQSxFQUFBLFNBQUEsT0FBQSxlQUFBLEVBQUE7QUFDQSxxQkFBQSxhQUFBLENBQUEsT0FBQSxTQUFBLEVBQUEsT0FBQSxZQUFBLEVBQUEsSUFBQTtBQUNBLEtBSEE7O0FBTUEsV0FBQSxXQUFBLEdBQUEsWUFBQTtBQUNBLHFCQUFBLFdBQUEsQ0FBQSxPQUFBLFlBQUEsRUFDQSxJQURBLENBQ0EsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxPQUFBLEVBQUEsRUFBQSxRQUFBLE9BQUEsU0FBQSxFQUFBLEVBQUEsRUFBQSxRQUFBLElBQUEsRUFBQTtBQUNBLFNBSEE7QUFJQSxLQUxBOzs7O0FBU0EsV0FBQSx3QkFBQSxHQUFBLEVBQUE7O0FBRUEsV0FBQSxhQUFBLEdBQUEsRUFBQTs7QUFFQSxpQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLElBQUEsTUFBQSxLQUFBLE9BQUEsWUFBQSxJQUFBLE9BQUEsd0JBQUEsQ0FBQSxPQUFBLENBQUEsSUFBQSxNQUFBLEtBQUEsQ0FBQSxDQUFBLEVBQUE7QUFDQSxtQkFBQSx3QkFBQSxDQUFBLElBQUEsQ0FBQSxJQUFBLE1BQUE7QUFDQSxTQUZBLE1BRUEsSUFBQSxJQUFBLE1BQUEsS0FBQSxPQUFBLFlBQUEsSUFBQSxPQUFBLHdCQUFBLENBQUEsT0FBQSxDQUFBLElBQUEsTUFBQSxLQUFBLENBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsd0JBQUEsQ0FBQSxJQUFBLENBQUEsSUFBQSxNQUFBO0FBQ0E7QUFDQSxLQU5BOztBQVFBLFdBQUEsYUFBQSxHQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxP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QUVBLFdBQUEsWUFBQSxHQUFBLFlBQUE7O0FBRUEsV0FBQSxVQUFBLEdBQUEsVUFBQTs7QUFFQSxXQUFBLGdCQUFBLEdBQUEsYUFBQSxNQUFBLEdBQUEsUUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxPQUFBLFNBQUEsQ0FBQSxJQUFBLENBQUEsTUFBQTs7QUFFQSxXQUFBLEdBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxXQUFBLENBQUEsSUFBQSxDQUFBLEdBQUE7QUFDQSxLQUZBOztBQUlBLFdBQUEsTUFBQSxHQUFBLE1BQUEsQzs7QUFFQSxXQUFBLGdCQUFBLEdBQUEsQ0FBQSxRQUFBLEVBQUEsU0FBQSxDQUFBOztBQUVBLFdBQUEsTUFBQSxHQUFBLGFBQUEsTUFBQTs7QUFFQSxXQUFBLGdCQUFBLEdBQUEsYUFBQSxnQkFBQTs7QUFFQSxXQUFBLFlBQUEsR0FBQSxVQUFBLFNBQUEsRUFBQTtBQUNBLFlBQUEsY0FBQSxlQUFBLElBQUEsY0FBQSxtQkFBQSxFQUFBLE9BQUEsSUFBQTtBQUNBLEtBRkE7O0FBSUEsV0FBQSxXQUFBLEdBQUEsVUFBQSxLQUFBLEVBQUE7QUFDQSxxQkFBQSxXQUFBLENBQUEsS0FBQSxFQUNBLElBREEsQ0FDQSxZQUFBO0FBQ0EsbUJBQUEsRUFBQSxDQUFBLE9BQUEsRUFBQSxFQUFBLFFBQUEsT0FBQSxNQUFBLEVBQUE7QUFDQSxTQUhBO0FBSUEsS0FMQTs7QUFPQSxXQUFBLGNBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxVQUFBLENBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxVQUFBLEtBQUEsT0FBQSxLQUFBLENBQUEsTUFBQSxJQUFBLElBQUEsV0FBQSxLQUFBLE9BQUEsS0FBQSxDQUFBLE1BQUEsRUFBQSxPQUFBLElBQUEsR0FBQSxJQUFBLFNBQUE7QUFDQSxTQUZBO0FBR0EsS0FKQTs7QUFNQSxXQUFBLGFBQUEsR0FBQSxFQUFBOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUEyQkEsV0FBQSxXQUFBLEdBQUEsYUFBQSxXQUFBO0FBRUEsQ0ExRUE7O0FDQUEsSUFBQSxPQUFBLENBQUEsY0FBQSxFQUFBLFVBQUEsS0FBQSxFQUFBLFlBQUEsRUFBQTs7QUFFQSxRQUFBLGVBQUEsRUFBQTs7QUFFQSxhQUFBLFNBQUEsQ0FBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLElBQUEsSUFBQTtBQUNBOztBQUVBLGlCQUFBLFlBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUJBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGNBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFNBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUJBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLE1BQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsSUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsR0FBQSxTQUFBLEVBQUEsSUFBQSxDQUFBO0FBQ0EsS0FGQTs7QUFJQSxpQkFBQSxhQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLElBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsa0JBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQUEsSUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLE1BQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLElBQUEsQ0FBQSx5QkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsRUFBQSxFQUFBLFdBQUEsU0FBQSxFQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsU0FBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsTUFBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxHQUFBLEdBQUEsR0FBQSxLQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsWUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxVQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsTUFBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxHQUFBLFVBQUEsR0FBQSxVQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsU0FBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxDQUFBLDRCQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLENBQUE7QUFDQSxLQUZBO0FBR0EsaUJBQUEsV0FBQSxHQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0EsY0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBO0FBQ0EsZUFBQSxNQUFBLElBQUEsQ0FBQSxlQUFBLEVBQUEsS0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUpBOztBQU1BLGlCQUFBLFdBQUEsR0FBQSxVQUFBLFlBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsYUFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLGFBQUEsU0FBQSxDQUFBO0FBQ0EsS0FGQTs7QUFJQSxpQkFBQSxnQkFBQSxHQUFBLFVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxJQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLGNBQUEsRUFBQSxXQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsUUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLE1BQUEsQ0FBQSxtQkFBQSxNQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsZUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsb0NBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsa0JBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUNBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsaUNBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGtCQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQ0FBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxPQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBLGFBQUEsRUFBQSxlQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxFQUFBO0FBQ0EsYUFBQSxNQUFBLEdBQUEsTUFBQTtBQUNBLGFBQUEsTUFBQSxHQUFBLGNBQUEsQ0FBQSxDQUFBO0FBQ0EsYUFBQSxhQUFBLEdBQUEsYUFBQTtBQUNBLGFBQUEsZUFBQSxHQUFBLGVBQUE7QUFDQSxhQUFBLFlBQUEsR0FBQSxZQUFB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QSxFQUFBO0FBQ0E7QUFMQSxLQUFBO0FBUUEsQ0FWQSIsImZpbGUiOiJtYWluLmpzIiwic291cmNlc0NvbnRlbnQiOlsiJ3VzZSBzdHJpY3QnO1xud2luZG93LmFwcCA9IGFuZ3VsYXIubW9kdWxlKCdGdWxsc3RhY2tHZW5lcmF0ZWRBcHAnLCBbJ2ZzYVByZUJ1aWx0JywgJ3VpLnJvdXRlcicsICd1aS5ib290c3RyYXAnLCAnbmdBbmltYXRlJ10pO1xuXG5hcHAuY29uZmlnKGZ1bmN0aW9uICgkdXJsUm91dGVyUHJvdmlkZXIsICRsb2NhdGlvblByb3ZpZGVyKSB7XG4gICAgLy8gVGhpcyB0dXJucyBvZmYgaGFzaGJhbmcgdXJscyAoLyNhYm91dCkgYW5kIGNoYW5nZXMgaXQgdG8gc29tZXRoaW5nIG5vcm1hbCAoL2Fib3V0KVxuICAgICRsb2NhdGlvblByb3ZpZGVyLmh0bWw1TW9kZSh0cnVlKTtcbiAgICAvLyBJZiB3ZSBnbyB0byBhIFVSTCB0aGF0IHVpLXJvdXRlciBkb2Vzbid0IGhhdmUgcmVnaXN0ZXJlZCwgZ28gdG8gdGhlIFwiL1wiIHVybC5cbiAgICAkdXJsUm91dGVyUHJvdmlkZXIub3RoZXJ3aXNlKCcvJyk7XG4gICAgLy8gVHJpZ2dlciBwYWdlIHJlZnJlc2ggd2hlbiBhY2Nlc3NpbmcgYW4gT0F1dGggcm91dGVcbiAgICAkdXJsUm91dGVyUHJvdmlkZXIud2hlbignL2F1dGgvOnByb3ZpZGVyJywgZnVuY3Rpb24gKCkge1xuICAgICAgICB3aW5kb3cubG9jYXRpb24ucmVsb2FkKCk7XG4gICAgfSk7XG59KTtcblxuLy8gVGhpcyBhcHAucnVuIGlzIGZvciBjb250cm9sbGluZyBhY2Nlc3MgdG8gc3BlY2lmaWMgc3RhdGVzLlxuYXBwLnJ1bihmdW5jdGlvbiAoJHJvb3RTY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICAgLy8gVGhlIGdpdmVuIHN0YXRlIHJlcXVpcmVzIGFuIGF1dGhlbnRpY2F0ZWQgdXNlci5cbiAgICB2YXIgZGVzdGluYXRpb25TdGF0ZVJlcXVpcmVzQXV0aCA9IGZ1bmN0aW9uIChzdGF0ZSkge1xuICAgICAgICByZXR1cm4gc3RhdGUuZGF0YSAmJiBzdGF0ZS5kYXRhLmF1dGhlbnRpY2F0ZTtcbiAgICB9O1xuXG4gICAgLy8gJHN0YXRlQ2hhbmdlU3RhcnQgaXMgYW4gZXZlbnQgZmlyZWRcbiAgICAvLyB3aGVuZXZlciB0aGUgcHJvY2VzcyBvZiBjaGFuZ2luZyBhIHN0YXRlIGJlZ2lucy5cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbiAoZXZlbnQsIHRvU3RhdGUsIHRvUGFyYW1zKSB7XG5cbiAgICAgICAgaWYgKCFkZXN0aW5hdGlvblN0YXRlUmVxdWlyZXNBdXRoKHRvU3RhdGUpKSB7XG4gICAgICAgICAgICAvLyBUaGUgZGVzdGluYXRpb24gc3RhdGUgZG9lcyBub3QgcmVxdWlyZSBhdXRoZW50aWNhdGlvblxuICAgICAgICAgICAgLy8gU2hvcnQgY2lyY3VpdCB3aXRoIHJldHVybi5cbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChBdXRoU2VydmljZS5pc0F1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAgICAgLy8gVGhlIHVzZXIgaXMgYXV0aGVudGljYXRlZC5cbiAgICAgICAgICAgIC8vIFNob3J0IGNpcmN1aXQgd2l0aCByZXR1cm4uXG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDYW5jZWwgbmF2aWdhdGluZyB0byBuZXcgc3RhdGUuXG4gICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG5cbiAgICAgICAgQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCkudGhlbihmdW5jdGlvbiAodXNlcikge1xuICAgICAgICAgICAgLy8gSWYgYSB1c2VyIGlzIHJldHJpZXZlZCwgdGhlbiByZW5hdmlnYXRlIHRvIHRoZSBkZXN0aW5hdGlvblxuICAgICAgICAgICAgLy8gKHRoZSBzZWNvbmQgdGltZSwgQXV0aFNlcnZpY2UuaXNBdXRoZW50aWNhdGVkKCkgd2lsbCB3b3JrKVxuICAgICAgICAgICAgLy8gb3RoZXJ3aXNlLCBpZiBubyB1c2VyIGlzIGxvZ2dlZCBpbiwgZ28gdG8gXCJsb2dpblwiIHN0YXRlLlxuICAgICAgICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgICAgICAgICAkc3RhdGUuZ28odG9TdGF0ZS5uYW1lLCB0b1BhcmFtcyk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnbG9naW4nKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG5cbiAgICB9KTtcblxufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuXG4gICAgLy8gUmVnaXN0ZXIgb3VyICphYm91dCogc3RhdGUuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2Fib3V0Jywge1xuICAgICAgICB1cmw6ICcvYWJvdXQnLFxuICAgICAgICBjb250cm9sbGVyOiAnQWJvdXRDb250cm9sbGVyJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9hYm91dC9hYm91dC5odG1sJ1xuICAgIH0pO1xuXG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ0Fib3V0Q29udHJvbGxlcicsIGZ1bmN0aW9uICgkc2NvcGUsIEZ1bGxzdGFja1BpY3MpIHtcblxuICAgIC8vIEltYWdlcyBvZiBiZWF1dGlmdWwgRnVsbHN0YWNrIHBlb3BsZS5cbiAgICAkc2NvcGUuaW1hZ2VzID0gXy5zaHVmZmxlKEZ1bGxzdGFja1BpY3MpO1xuXG59KTsiLCJhcHAuY29udHJvbGxlcignQ3JlYXRlZGJDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHN0YXRlLCBDcmVhdGVkYkZhY3RvcnkpIHtcblxuXHQkc2NvcGUuY3JlYXRlZERCID0gZmFsc2U7XG4gICAgICAgICRzY29wZS5jb2x1bW5BcnJheSA9IFtdO1xuXG5cdCRzY29wZS5hZGQgPSBmdW5jdGlvbigpIHtcblx0XHQkc2NvcGUuY29sdW1uQXJyYXkucHVzaCgnMScpO1xuXHR9XG5cblx0JHNjb3BlLmNyZWF0ZURCID0gZnVuY3Rpb24obmFtZSkge1xuXHRcdENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVEQihuYW1lKVxuXHRcdC50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcblx0XHRcdCRzY29wZS5jcmVhdGVkREIgPSBkYXRhO1xuXHRcdH0pXG5cdH1cblxuXHQkc2NvcGUuY3JlYXRlVGFibGUgPSBmdW5jdGlvbih0YWJsZSwgREIpe1xuXHRcdENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVUYWJsZSh0YWJsZSwgREIpXG5cdFx0XHQkc3RhdGUuZ28oJ1RhYmxlJywge2RiTmFtZTogJHNjb3BlLmNyZWF0ZWREQi5kYk5hbWV9LCB7cmVsb2FkOnRydWV9KVxuXHR9XG59KTtcbiIsImFwcC5mYWN0b3J5KCdDcmVhdGVkYkZhY3RvcnknLCBmdW5jdGlvbiAoJGh0dHApIHtcblxuXHR2YXIgQ3JlYXRlZGJGYWN0b3J5ID0ge307XG5cblx0ZnVuY3Rpb24gcmVzVG9EYXRhKHJlcykge1xuICAgICAgICByZXR1cm4gcmVzLmRhdGE7XG4gICAgfVxuXG4gICAgQ3JlYXRlZGJGYWN0b3J5LmNyZWF0ZURCID0gZnVuY3Rpb24oZGJOYW1lKSB7XG4gICAgXHRyZXR1cm4gJGh0dHAucG9zdCgnL2FwaS9tYXN0ZXJkYicsIGRiTmFtZSlcbiAgICBcdC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgIENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVUYWJsZSA9IGZ1bmN0aW9uKHRhYmxlLCBjcmVhdGVkREIpIHtcbiAgICB0YWJsZS5kYk5hbWUgPSBjcmVhdGVkREIuZGJOYW1lO1xuICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL2NsaWVudGRiJywgdGFibGUpXG4gICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgIH1cblxuXHRyZXR1cm4gQ3JlYXRlZGJGYWN0b3J5OyBcbn0pXG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdjcmVhdGVkYicsIHtcbiAgICAgICAgdXJsOiAnL2NyZWF0ZWRiJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jcmVhdGVkYi9jcmVhdGVkYi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0NyZWF0ZWRiQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgXHRsb2dnZWRJblVzZXI6IGZ1bmN0aW9uKEF1dGhTZXJ2aWNlKSB7XG4gICAgICAgIFx0XHRyZXR1cm4gQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCk7XG4gICAgICAgIFx0fVxuICAgICAgICB9XG4gICAgfSk7XG5cbn0pOyIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2RvY3MnLCB7XG4gICAgICAgIHVybDogJy9kb2NzJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9kb2NzL2RvY3MuaHRtbCdcbiAgICB9KTtcbn0pO1xuIiwiKGZ1bmN0aW9uICgpIHtcblxuICAgICd1c2Ugc3RyaWN0JztcblxuICAgIC8vIEhvcGUgeW91IGRpZG4ndCBmb3JnZXQgQW5ndWxhciEgRHVoLWRveS5cbiAgICBpZiAoIXdpbmRvdy5hbmd1bGFyKSB0aHJvdyBuZXcgRXJyb3IoJ0kgY2FuXFwndCBmaW5kIEFuZ3VsYXIhJyk7XG5cbiAgICB2YXIgYXBwID0gYW5ndWxhci5tb2R1bGUoJ2ZzYVByZUJ1aWx0JywgW10pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ1NvY2tldCcsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKCF3aW5kb3cuaW8pIHRocm93IG5ldyBFcnJvcignc29ja2V0LmlvIG5vdCBmb3VuZCEnKTtcbiAgICAgICAgcmV0dXJuIHdpbmRvdy5pbyh3aW5kb3cubG9jYXRpb24ub3JpZ2luKTtcbiAgICB9KTtcblxuICAgIC8vIEFVVEhfRVZFTlRTIGlzIHVzZWQgdGhyb3VnaG91dCBvdXIgYXBwIHRvXG4gICAgLy8gYnJvYWRjYXN0IGFuZCBsaXN0ZW4gZnJvbSBhbmQgdG8gdGhlICRyb290U2NvcGVcbiAgICAvLyBmb3IgaW1wb3J0YW50IGV2ZW50cyBhYm91dCBhdXRoZW50aWNhdGlvbiBmbG93LlxuICAgIGFwcC5jb25zdGFudCgnQVVUSF9FVkVOVFMnLCB7XG4gICAgICAgIGxvZ2luU3VjY2VzczogJ2F1dGgtbG9naW4tc3VjY2VzcycsXG4gICAgICAgIGxvZ2luRmFpbGVkOiAnYXV0aC1sb2dpbi1mYWlsZWQnLFxuICAgICAgICBsb2dvdXRTdWNjZXNzOiAnYXV0aC1sb2dvdXQtc3VjY2VzcycsXG4gICAgICAgIHNlc3Npb25UaW1lb3V0OiAnYXV0aC1zZXNzaW9uLXRpbWVvdXQnLFxuICAgICAgICBub3RBdXRoZW50aWNhdGVkOiAnYXV0aC1ub3QtYXV0aGVudGljYXRlZCcsXG4gICAgICAgIG5vdEF1dGhvcml6ZWQ6ICdhdXRoLW5vdC1hdXRob3JpemVkJ1xuICAgIH0pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ0F1dGhJbnRlcmNlcHRvcicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCAkcSwgQVVUSF9FVkVOVFMpIHtcbiAgICAgICAgdmFyIHN0YXR1c0RpY3QgPSB7XG4gICAgICAgICAgICA0MDE6IEFVVEhfRVZFTlRTLm5vdEF1dGhlbnRpY2F0ZWQsXG4gICAgICAgICAgICA0MDM6IEFVVEhfRVZFTlRTLm5vdEF1dGhvcml6ZWQsXG4gICAgICAgICAgICA0MTk6IEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LFxuICAgICAgICAgICAgNDQwOiBBVVRIX0VWRU5UUy5zZXNzaW9uVGltZW91dFxuICAgICAgICB9O1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KHN0YXR1c0RpY3RbcmVzcG9uc2Uuc3RhdHVzXSwgcmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVzcG9uc2UpXG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgfSk7XG5cbiAgICBhcHAuY29uZmlnKGZ1bmN0aW9uICgkaHR0cFByb3ZpZGVyKSB7XG4gICAgICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goW1xuICAgICAgICAgICAgJyRpbmplY3RvcicsXG4gICAgICAgICAgICBmdW5jdGlvbiAoJGluamVjdG9yKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRpbmplY3Rvci5nZXQoJ0F1dGhJbnRlcmNlcHRvcicpO1xuICAgICAgICAgICAgfVxuICAgICAgICBdKTtcbiAgICB9KTtcblxuICAgIGFwcC5zZXJ2aWNlKCdBdXRoU2VydmljZScsIGZ1bmN0aW9uICgkaHR0cCwgU2Vzc2lvbiwgJHJvb3RTY29wZSwgQVVUSF9FVkVOVFMsICRxKSB7XG5cbiAgICAgICAgZnVuY3Rpb24gb25TdWNjZXNzZnVsTG9naW4ocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHZhciBkYXRhID0gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgICAgIFNlc3Npb24uY3JlYXRlKGRhdGEuaWQsIGRhdGEudXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3QoQVVUSF9FVkVOVFMubG9naW5TdWNjZXNzKTtcbiAgICAgICAgICAgIHJldHVybiBkYXRhLnVzZXI7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBVc2VzIHRoZSBzZXNzaW9uIGZhY3RvcnkgdG8gc2VlIGlmIGFuXG4gICAgICAgIC8vIGF1dGhlbnRpY2F0ZWQgdXNlciBpcyBjdXJyZW50bHkgcmVnaXN0ZXJlZC5cbiAgICAgICAgdGhpcy5pc0F1dGhlbnRpY2F0ZWQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gISFTZXNzaW9uLnVzZXI7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5nZXRMb2dnZWRJblVzZXIgPSBmdW5jdGlvbiAoZnJvbVNlcnZlcikge1xuXG4gICAgICAgICAgICAvLyBJZiBhbiBhdXRoZW50aWNhdGVkIHNlc3Npb24gZXhpc3RzLCB3ZVxuICAgICAgICAgICAgLy8gcmV0dXJuIHRoZSB1c2VyIGF0dGFjaGVkIHRvIHRoYXQgc2Vzc2lvblxuICAgICAgICAgICAgLy8gd2l0aCBhIHByb21pc2UuIFRoaXMgZW5zdXJlcyB0aGF0IHdlIGNhblxuICAgICAgICAgICAgLy8gYWx3YXlzIGludGVyZmFjZSB3aXRoIHRoaXMgbWV0aG9kIGFzeW5jaHJvbm91c2x5LlxuXG4gICAgICAgICAgICAvLyBPcHRpb25hbGx5LCBpZiB0cnVlIGlzIGdpdmVuIGFzIHRoZSBmcm9tU2VydmVyIHBhcmFtZXRlcixcbiAgICAgICAgICAgIC8vIHRoZW4gdGhpcyBjYWNoZWQgdmFsdWUgd2lsbCBub3QgYmUgdXNlZC5cblxuICAgICAgICAgICAgaWYgKHRoaXMuaXNBdXRoZW50aWNhdGVkKCkgJiYgZnJvbVNlcnZlciAhPT0gdHJ1ZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS53aGVuKFNlc3Npb24udXNlcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIE1ha2UgcmVxdWVzdCBHRVQgL3Nlc3Npb24uXG4gICAgICAgICAgICAvLyBJZiBpdCByZXR1cm5zIGEgdXNlciwgY2FsbCBvblN1Y2Nlc3NmdWxMb2dpbiB3aXRoIHRoZSByZXNwb25zZS5cbiAgICAgICAgICAgIC8vIElmIGl0IHJldHVybnMgYSA0MDEgcmVzcG9uc2UsIHdlIGNhdGNoIGl0IGFuZCBpbnN0ZWFkIHJlc29sdmUgdG8gbnVsbC5cbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9zZXNzaW9uJykudGhlbihvblN1Y2Nlc3NmdWxMb2dpbikuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLnNpZ251cCA9IGZ1bmN0aW9uKGNyZWRlbnRpYWxzKXtcbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvc2lnbnVwJywgY3JlZGVudGlhbHMpXG4gICAgICAgICAgICAudGhlbihvblN1Y2Nlc3NmdWxMb2dpbilcbiAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdCh7IG1lc3NhZ2U6ICdJbnZhbGlkIHNpZ251cCBjcmVkZW50aWFscy4nIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5sb2dpbiA9IGZ1bmN0aW9uIChjcmVkZW50aWFscykge1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9sb2dpbicsIGNyZWRlbnRpYWxzKVxuICAgICAgICAgICAgICAgIC50aGVuKG9uU3VjY2Vzc2Z1bExvZ2luKVxuICAgICAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QoeyBtZXNzYWdlOiAnSW52YWxpZCBsb2dpbiBjcmVkZW50aWFscy4nIH0pO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2xvZ291dCcpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIFNlc3Npb24uZGVzdHJveSgpO1xuICAgICAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChBVVRIX0VWRU5UUy5sb2dvdXRTdWNjZXNzKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuXG4gICAgfSk7XG5cbiAgICBhcHAuc2VydmljZSgnU2Vzc2lvbicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBVVRIX0VWRU5UUykge1xuXG4gICAgICAgIHZhciBzZWxmID0gdGhpcztcblxuICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5ub3RBdXRoZW50aWNhdGVkLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBzZWxmLmRlc3Ryb3koKTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHNlbGYuZGVzdHJveSgpO1xuICAgICAgICB9KTtcblxuICAgICAgICB0aGlzLmlkID0gbnVsbDtcbiAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcblxuICAgICAgICB0aGlzLmNyZWF0ZSA9IGZ1bmN0aW9uIChzZXNzaW9uSWQsIHVzZXIpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBzZXNzaW9uSWQ7XG4gICAgICAgICAgICB0aGlzLnVzZXIgPSB1c2VyO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMuZGVzdHJveSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBudWxsO1xuICAgICAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcbiAgICAgICAgfTtcblxuICAgIH0pO1xuXG59KSgpO1xuIiwiYXBwLmNvbnRyb2xsZXIoJ0hvbWVDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgYWxsRGJzLCAkc3RhdGUpIHtcblxuXHQkc2NvcGUuYWxsRGJzID0gYWxsRGJzO1xufSk7XG4iLCJhcHAuZmFjdG9yeSgnSG9tZUZhY3RvcnknLCBmdW5jdGlvbiAoJGh0dHApIHtcblxuXHR2YXIgSG9tZUZhY3RvcnkgPSB7fTtcblxuXHRmdW5jdGlvbiByZXNUb0RhdGEocmVzKSB7XG4gICAgICAgIHJldHVybiByZXMuZGF0YTtcbiAgICB9XG5cbiAgICBIb21lRmFjdG9yeS5nZXRBbGxEYnMgPSBmdW5jdGlvbigpe1xuICAgIFx0cmV0dXJuICRodHRwLmdldCgnL2FwaS9tYXN0ZXJkYicpXG4gICAgXHQudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgSG9tZUZhY3RvcnkuZGVsZXRlREIgPSBmdW5jdGlvbihuYW1lKXtcbiAgICBcdHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvbWFzdGVyZGIvJyArIG5hbWUpXG4gICAgXHQudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG5cdHJldHVybiBIb21lRmFjdG9yeTsgXG59KSIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ0hvbWUnLCB7XG4gICAgICAgIHVybDogJy9ob21lJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9Ib21lL0hvbWUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdIb21lQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgXHRhbGxEYnM6IGZ1bmN0aW9uKEhvbWVGYWN0b3J5KXtcbiAgICAgICAgXHRcdHJldHVybiBIb21lRmFjdG9yeS5nZXRBbGxEYnMoKTtcbiAgICAgICAgXHR9LFxuICAgICAgICAgICAgbG9nZ2VkSW5Vc2VyOiBmdW5jdGlvbiAoQXV0aFNlcnZpY2UpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KTtcbn0pOyIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2xhbmRpbmdQYWdlJywge1xuICAgICAgICB1cmw6ICcvJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9sYW5kaW5nUGFnZS9sYW5kaW5nUGFnZS5odG1sJ1xuICAgICAgICB9XG4gICAgKTtcblxufSk7IiwiYXBwLmNvbmZpZyhmdW5jdGlvbigkc3RhdGVQcm92aWRlcikge1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2xvZ2luJywge1xuICAgICAgICB1cmw6ICcvbG9naW4nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2xvZ2luL2xvZ2luLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnTG9naW5DdHJsJ1xuICAgIH0pO1xuXG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ0xvZ2luQ3RybCcsIGZ1bmN0aW9uKCRzY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICAgJHNjb3BlLmxvZ2luID0ge307XG4gICAgJHNjb3BlLmVycm9yID0gbnVsbDtcblxuICAgICRzY29wZS5zZW5kTG9naW4gPSBmdW5jdGlvbihsb2dpbkluZm8pIHtcblxuICAgICAgICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICAgICAgIEF1dGhTZXJ2aWNlLmxvZ2luKGxvZ2luSW5mbykudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbygnSG9tZScpO1xuICAgICAgICB9KS5jYXRjaChmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICRzY29wZS5lcnJvciA9ICdJbnZhbGlkIGxvZ2luIGNyZWRlbnRpYWxzLic7XG4gICAgICAgIH0pO1xuXG4gICAgfTtcblxufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ21lbWJlcnNPbmx5Jywge1xuICAgICAgICB1cmw6ICcvbWVtYmVycy1hcmVhJyxcbiAgICAgICAgdGVtcGxhdGU6ICc8aW1nIG5nLXJlcGVhdD1cIml0ZW0gaW4gc3Rhc2hcIiB3aWR0aD1cIjMwMFwiIG5nLXNyYz1cInt7IGl0ZW0gfX1cIiAvPicsXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uICgkc2NvcGUsIFNlY3JldFN0YXNoKSB7XG4gICAgICAgICAgICBTZWNyZXRTdGFzaC5nZXRTdGFzaCgpLnRoZW4oZnVuY3Rpb24gKHN0YXNoKSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnN0YXNoID0gc3Rhc2g7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSxcbiAgICAgICAgLy8gVGhlIGZvbGxvd2luZyBkYXRhLmF1dGhlbnRpY2F0ZSBpcyByZWFkIGJ5IGFuIGV2ZW50IGxpc3RlbmVyXG4gICAgICAgIC8vIHRoYXQgY29udHJvbHMgYWNjZXNzIHRvIHRoaXMgc3RhdGUuIFJlZmVyIHRvIGFwcC5qcy5cbiAgICAgICAgZGF0YToge1xuICAgICAgICAgICAgYXV0aGVudGljYXRlOiB0cnVlXG4gICAgICAgIH1cbiAgICB9KTtcblxufSk7XG5cbmFwcC5mYWN0b3J5KCdTZWNyZXRTdGFzaCcsIGZ1bmN0aW9uICgkaHR0cCkge1xuXG4gICAgdmFyIGdldFN0YXNoID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL21lbWJlcnMvc2VjcmV0LXN0YXNoJykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5kYXRhO1xuICAgICAgICB9KTtcbiAgICB9O1xuXG4gICAgcmV0dXJuIHtcbiAgICAgICAgZ2V0U3Rhc2g6IGdldFN0YXNoXG4gICAgfTtcblxufSk7IiwiJ3VzZSBzdHJpY3QnO1xuXG5hcHAuZGlyZWN0aXZlKCdvYXV0aEJ1dHRvbicsIGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIHtcbiAgICBzY29wZToge1xuICAgICAgcHJvdmlkZXJOYW1lOiAnQCdcbiAgICB9LFxuICAgIHJlc3RyaWN0OiAnRScsXG4gICAgdGVtcGxhdGVVcmw6ICcvanMvb2F1dGgvb2F1dGgtYnV0dG9uLmh0bWwnXG4gIH1cbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdzaWdudXAnLCB7XG4gICAgICAgIHVybDogJy9zaWdudXAnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3NpZ251cC9zaWdudXAuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdTaWdudXBDdHJsJ1xuICAgIH0pO1xuXG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ1NpZ251cEN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBBdXRoU2VydmljZSwgJHN0YXRlKSB7XG5cbiAgICAkc2NvcGUuc2lnbnVwID0ge307XG4gICAgJHNjb3BlLmVycm9yID0gbnVsbDtcblxuICAgICRzY29wZS5zZW5kU2lnbnVwID0gZnVuY3Rpb24gKHNpZ251cEluZm8pIHtcbiAgICAgICAgJHNjb3BlLmVycm9yID0gbnVsbDtcbiAgICAgICAgQXV0aFNlcnZpY2Uuc2lnbnVwKHNpZ251cEluZm8pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKCdob21lJyk7XG4gICAgICAgIH0pLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICRzY29wZS5lcnJvciA9ICdPb3BzLCBjYW5ub3Qgc2lnbiB1cCB3aXRoIHRob3NlIGNyZWRlbnRpYWxzLic7XG4gICAgICAgIH0pO1xuXG4gICAgfTtcblxufSk7XG4iLCJhcHAuY29udHJvbGxlcignQXNzb2NpYXRpb25JbnN0YW5jZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCAkdWliTW9kYWxJbnN0YW5jZSwgZm9yZWlnbkNvbHMsIFRhYmxlRmFjdG9yeSwgSG9tZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgJHN0YXRlLCBmb3JUYWJsZSwgZm9yVGFibGVOYW1lLCBjdXJyVGFibGUsIGNvbE5hbWUsIGlkMSkge1xuXG4gICRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lO1xuXG4gICRzY29wZS5zaW5nbGVUYWJsZSA9IGZvclRhYmxlO1xuXG4gICRzY29wZS5UYWJsZU5hbWUgPSBmb3JUYWJsZU5hbWU7XG5cbiAgJHNjb3BlLmN1cnJUYWJsZSA9IGN1cnJUYWJsZTtcblxuICAkc2NvcGUuY29sTmFtZSA9IGNvbE5hbWU7XG5cbiAgJHNjb3BlLmlkMSA9IGlkMTtcblxuICAkc2NvcGUuc2V0U2VsZWN0ZWQgPSBmdW5jdGlvbigpe1xuXG4gICAgJHNjb3BlLmN1cnJSb3cgPSB0aGlzLnJvdztcbiAgICBjb25zb2xlLmxvZygkc2NvcGUuY3VyclJvdyk7XG4gIH1cblxuIFxuXG4gIGZ1bmN0aW9uIENyZWF0ZUNvbHVtbnMoKXtcbiAgICAkc2NvcGUuY29sdW1ucyA9IFtdO1xuICAgIHZhciB0YWJsZSA9IGZvclRhYmxlWzBdO1xuXG5cbiAgICBmb3IodmFyIHByb3AgaW4gdGFibGUpe1xuICAgICAgaWYocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jyl7XG4gICAgICAgICRzY29wZS5jb2x1bW5zLnB1c2gocHJvcCk7ICBcbiAgICAgIH0gXG4gICAgfVxuICB9XG5cbiAgICBDcmVhdGVDb2x1bW5zKCk7XG5cblxuICAgIC8vdGhpcyBmdW5jdGlvbiB3aWxsIHJlIHJ1biB3aGVuIHRoZSBmaWx0ZXIgZnVuY3Rpb24gaXMgaW52b2tlZCwgaW4gb3JkZXIgdG8gcmVwb3B1bGF0ZSB0aGUgdGFibGVcbiAgICBmdW5jdGlvbiBDcmVhdGVSb3dzKCkge1xuICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheSA9IFtdO1xuICAgICAgICBmb3JUYWJsZS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgdmFyIHJvd1ZhbHVlcyA9IFtdO1xuICAgICAgICAgICAgZm9yICh2YXIgcHJvcCBpbiByb3cpIHtcbiAgICAgICAgICAgICAgICBpZiAocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jykgcm93VmFsdWVzLnB1c2gocm93W3Byb3BdKVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkucHVzaChyb3dWYWx1ZXMpXG4gICAgICAgIH0pXG4gICAgfVxuXG4gICAgLy8gU29ydCB0aGUgdmFsdWVzIGluIHNpbmdsZVRhYmxlIHNvIHRoYXQgYWxsIHRoZSB2YWx1ZXMgZm9yIGEgZ2l2ZW4gcm93IGFyZSBncm91cGVkXG4gICAgQ3JlYXRlUm93cygpO1xuXG5cbiAgJHNjb3BlLnNldEZvcmVpZ25LZXkgPSBmdW5jdGlvbihkYk5hbWUsIHRibE5hbWUsIGNvbE5hbWUsIGlkMSwgaWQyKXtcbiAgICAkdWliTW9kYWxJbnN0YW5jZS5jbG9zZSgpO1xuICAgIFRhYmxlRmFjdG9yeS5zZXRGb3JlaWduS2V5KGRiTmFtZSwgdGJsTmFtZSwgY29sTmFtZSwgaWQxLCBpZDIpXG4gICAgLnRoZW4oZnVuY3Rpb24oKXtcbiAgICAgICAgJHN0YXRlLmdvKCdUYWJsZS5TaW5nbGUnLCB7IGRiTmFtZTogJHNjb3BlLmRiTmFtZSwgdGFibGVOYW1lOiAkc2NvcGUuY3VyclRhYmxlIH0sIHsgcmVsb2FkOiB0cnVlIH0pXG4gICAgfSlcbiAgfVxuXG5cblxuICAkc2NvcGUub2sgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoJHNjb3BlLnNlbGVjdGVkLml0ZW0pO1xuICB9O1xuXG4gICRzY29wZS5jYW5jZWwgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuZGlzbWlzcygnY2FuY2VsJyk7XG4gIH07XG59KTsiLCJhcHAuY29udHJvbGxlcignZGVsZXRlREJDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHVpYk1vZGFsLCAkbG9nKSB7XG5cbiAgJHNjb3BlLml0ZW1zID0gWydpdGVtMScsICdpdGVtMicsICdpdGVtMyddO1xuXG4gICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9IHRydWU7XG5cbiAgJHNjb3BlLm9wZW4gPSBmdW5jdGlvbiAoc2l6ZSkge1xuXG4gICAgdmFyIG1vZGFsSW5zdGFuY2UgPSAkdWliTW9kYWwub3Blbih7XG4gICAgICBhbmltYXRpb246ICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCxcbiAgICAgIHRlbXBsYXRlVXJsOiAnZGVsZXRlREJDb250ZW50Lmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ2RlbGV0ZURCSW5zdGFuY2VDdHJsJyxcbiAgICAgIHNpemU6IHNpemUsXG4gICAgICByZXNvbHZlOiB7XG4gICAgICAgIGl0ZW1zOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgcmV0dXJuICRzY29wZS5pdGVtcztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbiAoc2VsZWN0ZWRJdGVtKSB7XG4gICAgICAkc2NvcGUuc2VsZWN0ZWQgPSBzZWxlY3RlZEl0ZW07XG4gICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgJGxvZy5pbmZvKCdNb2RhbCBkaXNtaXNzZWQgYXQ6ICcgKyBuZXcgRGF0ZSgpKTtcbiAgICB9KTtcbiAgfTtcblxuICAkc2NvcGUudG9nZ2xlQW5pbWF0aW9uID0gZnVuY3Rpb24gKCkge1xuICAgICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9ICEkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQ7XG4gIH07XG5cbn0pO1xuXG5hcHAuY29udHJvbGxlcignZGVsZXRlREJJbnN0YW5jZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCAkdWliTW9kYWxJbnN0YW5jZSwgaXRlbXMsIFRhYmxlRmFjdG9yeSwgSG9tZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgJHN0YXRlKSB7XG5cblxuICAkc2NvcGUuZHJvcERiVGV4dCA9ICdEUk9QIERBVEFCQVNFJ1xuICAkc2NvcGUuZGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZTtcblxuICAkc2NvcGUuZGVsZXRlVGhlRGIgPSBmdW5jdGlvbigpe1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmNsb3NlKCRzY29wZS5zZWxlY3RlZC5pdGVtKTtcbiAgICBUYWJsZUZhY3RvcnkuZGVsZXRlRGIoJHNjb3BlLmRiTmFtZSlcbiAgICAudGhlbihmdW5jdGlvbigpe1xuICAgICAgSG9tZUZhY3RvcnkuZGVsZXRlREIoJHNjb3BlLmRiTmFtZSlcbiAgICB9KVxuICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgJHN0YXRlLmdvKCdIb21lJywge30sIHtyZWxvYWQgOiB0cnVlfSlcbiAgICB9KVxuICB9XG5cbiAgJHNjb3BlLml0ZW1zID0gaXRlbXM7XG4gICRzY29wZS5zZWxlY3RlZCA9IHtcbiAgICBpdGVtOiAkc2NvcGUuaXRlbXNbMF1cbiAgfTtcblxuICAkc2NvcGUub2sgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoJHNjb3BlLnNlbGVjdGVkLml0ZW0pO1xuICB9O1xuXG4gICRzY29wZS5jYW5jZWwgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuZGlzbWlzcygnY2FuY2VsJyk7XG4gIH07XG59KTsiLCJhcHAuY29udHJvbGxlcignRGVsZXRlRGJDdHJsJywgZnVuY3Rpb24gKCRzY29wZSkge1xuXG4gICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9IHRydWU7XG5cbiAgJHNjb3BlLm9wZW4gPSBmdW5jdGlvbiAoc2l6ZSkge1xuXG4gICAgdmFyIG1vZGFsSW5zdGFuY2UgPSAkdWliTW9kYWwub3Blbih7XG4gICAgICBhbmltYXRpb246ICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCxcbiAgICAgIHRlbXBsYXRlVXJsOiAnZGVsZXRlRGJDb250ZW50Lmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0RlbGV0ZURiSW5zdGFuY2VDdHJsJyxcbiAgICAgIHNpemU6IHNpemUsXG4gICAgICByZXNvbHZlOiB7XG4gICAgICAgIGl0ZW1zOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgcmV0dXJuICRzY29wZS5pdGVtcztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbiAoc2VsZWN0ZWRJdGVtKSB7XG4gICAgICAkc2NvcGUuc2VsZWN0ZWQgPSBzZWxlY3RlZEl0ZW07XG4gICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgJGxvZy5pbmZvKCdNb2RhbCBkaXNtaXNzZWQgYXQ6ICcgKyBuZXcgRGF0ZSgpKTtcbiAgICB9KTtcbiAgfTtcblxufSk7XG5cblxuYXBwLmNvbnRyb2xsZXIoJ0RlbGV0ZURiSW5zdGFuY2VDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHVpYk1vZGFsSW5zdGFuY2UsIGl0ZW1zLCAkc3RhdGVQYXJhbXMsIFRhYmxlRmFjdG9yeSkge1xuXG4gICRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lXG5cbiAgJHNjb3BlLmRyb3BEYXRhYmFzZSA9ICdEUk9QIERBVEFCQVNFJ1xuXG4gICRzY29wZS5kZWxldGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgVGFibGVGYWN0b3J5LmRlbGV0ZURiKCRzY29wZS5kYk5hbWUpXG4gICAgLy8gJHN0YXRlLmdvKCdIb21lJywge30sIHtyZWxvYWQgOiB0cnVlfSlcbiAgfTtcblxuICAkc2NvcGUuY2FuY2VsID0gZnVuY3Rpb24gKCkge1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmRpc21pc3MoJ2NhbmNlbCcpO1xuICB9O1xufSk7IiwiYXBwLmNvbnRyb2xsZXIoJ0pvaW5UYWJsZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgam9pblRhYmxlKSB7XG5cbiAgICAkc2NvcGUuam9pblRhYmxlID0gam9pblRhYmxlO1xuXG5cblx0ZnVuY3Rpb24gQ3JlYXRlQ29sdW1ucygpe1xuXHRcdCRzY29wZS5jb2x1bW5zID0gW107XG5cdFx0dmFyIHRhYmxlID0gJHNjb3BlLmpvaW5UYWJsZVswXTtcblxuXG5cdFx0Zm9yKHZhciBwcm9wIGluIHRhYmxlKXtcblx0XHRcdGlmKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpe1xuXHRcdFx0XHQkc2NvcGUuY29sdW1ucy5wdXNoKHByb3ApO1x0XG5cdFx0XHR9IFxuXHRcdH1cblx0fVxuXG4gICAgQ3JlYXRlQ29sdW1ucygpO1xuXG5cbiAgICAvL3RoaXMgZnVuY3Rpb24gd2lsbCByZSBydW4gd2hlbiB0aGUgZmlsdGVyIGZ1bmN0aW9uIGlzIGludm9rZWQsIGluIG9yZGVyIHRvIHJlcG9wdWxhdGUgdGhlIHRhYmxlXG4gICAgZnVuY3Rpb24gQ3JlYXRlUm93cygpIHtcbiAgICBcdHZhciBhbGlhcztcbiAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkgPSBbXTtcbiAgICAgICAgam9pblRhYmxlLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICB2YXIgcm93VmFsdWVzID0gW107XG4gICAgICAgICAgICBmb3IgKHZhciBwcm9wIGluIHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKSByb3dWYWx1ZXMucHVzaChyb3dbcHJvcF0pXG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheS5wdXNoKHJvd1ZhbHVlcylcbiAgICAgICAgfSlcbiAgICB9XG5cbiAgICAvLyBTb3J0IHRoZSB2YWx1ZXMgaW4gc2luZ2xlVGFibGUgc28gdGhhdCBhbGwgdGhlIHZhbHVlcyBmb3IgYSBnaXZlbiByb3cgYXJlIGdyb3VwZWRcbiAgICBDcmVhdGVSb3dzKCk7XG5cblxufSkiLCJhcHAuY29udHJvbGxlcignUXVlcnlUYWJsZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuXG5cblx0ZnVuY3Rpb24gQ3JlYXRlQ29sdW1ucygpe1xuXHRcdCRzY29wZS5jb2x1bW5zID0gW107XG5cdFx0dmFyIHRhYmxlID0gJHNjb3BlLmpvaW5UYWJsZVswXTtcblxuXG5cdFx0Zm9yKHZhciBwcm9wIGluIHRhYmxlKXtcblx0XHRcdGlmKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpe1xuXHRcdFx0XHQkc2NvcGUuY29sdW1ucy5wdXNoKHByb3ApO1x0XG5cdFx0XHR9IFxuXHRcdH1cblx0fVxuXG4gICAgQ3JlYXRlQ29sdW1ucygpO1xuXG5cbiAgICAvL3RoaXMgZnVuY3Rpb24gd2lsbCByZSBydW4gd2hlbiB0aGUgZmlsdGVyIGZ1bmN0aW9uIGlzIGludm9rZWQsIGluIG9yZGVyIHRvIHJlcG9wdWxhdGUgdGhlIHRhYmxlXG4gICAgZnVuY3Rpb24gQ3JlYXRlUm93cygpIHtcbiAgICBcdHZhciBhbGlhcztcbiAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkgPSBbXTtcbiAgICAgICAgam9pblRhYmxlLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICB2YXIgcm93VmFsdWVzID0gW107XG4gICAgICAgICAgICBmb3IgKHZhciBwcm9wIGluIHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKSByb3dWYWx1ZXMucHVzaChyb3dbcHJvcF0pXG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheS5wdXNoKHJvd1ZhbHVlcylcbiAgICAgICAgfSlcbiAgICB9XG5cbiAgICAvLyBTb3J0IHRoZSB2YWx1ZXMgaW4gc2luZ2xlVGFibGUgc28gdGhhdCBhbGwgdGhlIHZhbHVlcyBmb3IgYSBnaXZlbiByb3cgYXJlIGdyb3VwZWRcbiAgICBDcmVhdGVSb3dzKCk7XG5cblxufSkiLCJhcHAuY29udHJvbGxlcignU2luZ2xlVGFibGVDdHJsJywgZnVuY3Rpb24oJHNjb3BlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgc2luZ2xlVGFibGUsICR3aW5kb3csICRzdGF0ZSwgJHVpYk1vZGFsLCBhc3NvY2lhdGlvbnMsICRsb2cpIHtcblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9QdXR0aW5nIHN0dWZmIG9uIHNjb3BlLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuXG4gICAgJHNjb3BlLnRoZURiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG4gICAgJHNjb3BlLnRoZVRhYmxlTmFtZSA9ICRzdGF0ZVBhcmFtcy50YWJsZU5hbWU7XG4gICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gc2luZ2xlVGFibGVbMF07XG4gICAgJHNjb3BlLnNlbGVjdGVkQWxsID0gZmFsc2U7XG4gICAgJHNjb3BlLmFzc29jaWF0aW9ucyA9IGFzc29jaWF0aW9ucztcblxuXG5cbiAgICBmdW5jdGlvbiBmb3JlaWduQ29sdW1uT2JqKCkge1xuICAgICAgICB2YXIgZm9yZWlnbkNvbHMgPSB7fTtcbiAgICAgICAgJHNjb3BlLmFzc29jaWF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgaWYgKHJvdy5UYWJsZTEgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgcm93LlJlbGF0aW9uc2hpcDEgPT09ICdoYXNPbmUnKSB7XG4gICAgICAgICAgICAgICAgZm9yZWlnbkNvbHNbcm93LkFsaWFzMV0gPSByb3cuVGFibGUyXG4gICAgICAgICAgICB9IGVsc2UgaWYgKHJvdy5UYWJsZTIgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgcm93LlJlbGF0aW9uc2hpcDIgPT09ICdoYXNPbmUnKSB7XG4gICAgICAgICAgICAgICAgZm9yZWlnbkNvbHNbcm93LkFsaWFzMl0gPSByb3cuVGFibGUxXG4gICAgICAgICAgICB9XG4gICAgICAgIH0pXG4gICAgICAgICRzY29wZS5mb3JlaWduQ29scyA9IGZvcmVpZ25Db2xzO1xuICAgIH1cblxuICAgIGZvcmVpZ25Db2x1bW5PYmooKTtcblxuXG4gICAgJHNjb3BlLmN1cnJlbnRUYWJsZSA9ICRzdGF0ZVBhcmFtcztcblxuICAgICRzY29wZS5teUluZGV4ID0gMTtcblxuICAgICRzY29wZS5pZHMgPSAkc2NvcGUuc2luZ2xlVGFibGUubWFwKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICByZXR1cm4gcm93LmlkO1xuICAgIH0pXG5cbiAgICAvL2RlbGV0ZSBhIHJvdyBcbiAgICAkc2NvcGUuc2hvd0RlbGV0ZSA9IGZhbHNlO1xuICAgICRzY29wZS50b2dnbGVEZWxldGUgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgJHNjb3BlLnNob3dEZWxldGUgPSAhJHNjb3BlLnNob3dEZWxldGVcbiAgICB9XG5cbiAgICAkc2NvcGUuZGVsZXRlU2VsZWN0ZWQgPSBmdW5jdGlvbihkYiwgdGFibGUsIGluc3RhbmNlQXJyYXkpIHtcbiAgICAgICAgaW5zdGFuY2VBcnJheS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgaWYgKHJvdy5zZWxlY3RlZCkge1xuICAgICAgICAgICAgICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVSb3coZGIsIHRhYmxlLCByb3dbJ3ZhbHVlcyddWzBdWyd2YWx1ZSddKVxuICAgICAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHJlc3VsdDtcbiAgICAgICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSlcbiAgICAgICAgJHNjb3BlLnNob3dEZWxldGUgPSBmYWxzZTtcbiAgICB9XG5cbiAgICAkc2NvcGUuc2VsZWN0QWxsID0gZnVuY3Rpb24oaW5zdGFuY2VBcnJheSkge1xuICAgICAgICBpZiAoJHNjb3BlLnNlbGVjdGVkQWxsKSB7XG4gICAgICAgICAgICBpbnN0YW5jZUFycmF5LmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICAgICAgcm93LnNlbGVjdGVkID0gdHJ1ZTtcbiAgICAgICAgICAgIH0pXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBpbnN0YW5jZUFycmF5LmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICAgICAgcm93LnNlbGVjdGVkID0gZmFsc2U7XG4gICAgICAgICAgICB9KVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLnVuY2hlY2tTZWxlY3RBbGwgPSBmdW5jdGlvbihpbnN0YW5jZUFycmF5KSB7XG4gICAgICAgIGlmICgkc2NvcGUuc2VsZWN0ZWRBbGwgPT09IHRydWUpIHtcbiAgICAgICAgICAgICRzY29wZS5zZWxlY3RlZEFsbCA9IGZhbHNlO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLnJlbW92ZVJvdyA9IGZ1bmN0aW9uKGRiLCB0YWJsZSwgcm93KSB7XG4gICAgICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVSb3coZGIsIHRhYmxlLCByb3cpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgfSlcbiAgICB9XG5cbiAgICAkc2NvcGUucmVtb3ZlQ29sdW1uID0gZnVuY3Rpb24oZGIsIHRhYmxlLCBjb2x1bW5OYW1lKSB7XG4gICAgICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVDb2x1bW4oZGIsIHRhYmxlLCBjb2x1bW5OYW1lKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0O1xuICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICBDcmVhdGVDb2x1bW5zKCk7XG4gICAgICAgICAgICB9KVxuICAgIH1cblxuICAgICRzY29wZS5uZXdSb3cgPSBmdW5jdGlvbihkYiwgdGFibGUsIGFycikge1xuICAgICAgICB2YXIgYWxsSWRzID0gW107XG4gICAgICAgIGFyci5mb3JFYWNoKGZ1bmN0aW9uKHJvd0RhdGEpIHtcbiAgICAgICAgICAgIGFsbElkcy5wdXNoKHJvd0RhdGEudmFsdWVzWzBdLnZhbHVlKVxuICAgICAgICB9KVxuICAgICAgICB2YXIgc29ydGVkID0gYWxsSWRzLnNvcnQoZnVuY3Rpb24oYSwgYikge1xuICAgICAgICAgICAgcmV0dXJuIGIgLSBhXG4gICAgICAgIH0pXG4gICAgICAgIGlmIChzb3J0ZWQubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgVGFibGVGYWN0b3J5LmFkZFJvdyhkYiwgdGFibGUsIHNvcnRlZFswXSArIDEpXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHJlc3VsdDtcbiAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgIH0pXG5cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIFRhYmxlRmFjdG9yeS5hZGRSb3coZGIsIHRhYmxlLCAxKVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLmFkZENvbHVtbiA9IGZ1bmN0aW9uKGRiLCB0YWJsZSkge1xuICAgICAgICB2YXIgY29sTnVtcyA9ICRzY29wZS5jb2x1bW5zLmpvaW4oJyAnKS5tYXRjaCgvXFxkKy9nKTtcbiAgICAgICAgaWYgKGNvbE51bXMpIHtcbiAgICAgICAgICAgIHZhciBzb3J0ZWROdW1zID0gY29sTnVtcy5zb3J0KGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gYiAtIGFcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB2YXIgbnVtSW5OZXcgPSBOdW1iZXIoc29ydGVkTnVtc1swXSkgKyAxO1xuICAgICAgICAgICAgdmFyIG5hbWVOZXdDb2wgPSAnQ29sdW1uICcgKyBudW1Jbk5ldy50b1N0cmluZygpO1xuXG4gICAgICAgICAgICBUYWJsZUZhY3RvcnkuYWRkQ29sdW1uKGRiLCB0YWJsZSwgbmFtZU5ld0NvbClcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSgkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKVxuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24odGhlVGFibGUpIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gdGhlVGFibGVbMF07XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZUNvbHVtbnMoKTtcbiAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB2YXIgbmV4dENvbE51bSA9ICRzY29wZS5jb2x1bW5zLmxlbmd0aCArIDE7XG4gICAgICAgICAgICB2YXIgbmV3Q29sTmFtZSA9ICdDb2x1bW4gJyArIG5leHRDb2xOdW07XG4gICAgICAgICAgICBUYWJsZUZhY3RvcnkuYWRkQ29sdW1uKGRiLCB0YWJsZSwgJ0NvbHVtbiAxJylcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSgkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKVxuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24odGhlVGFibGUpIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gdGhlVGFibGVbMF07XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZUNvbHVtbnMoKTtcbiAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgIH1cblxuICAgIH1cblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9Pcmdhbml6aW5nIHN0dWZmIGludG8gYXJyYXlzLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuXG4gICAgLy8gR2V0IGFsbCBvZiB0aGUgY29sdW1ucyB0byBjcmVhdGUgdGhlIGNvbHVtbnMgb24gdGhlIGJvb3RzdHJhcCB0YWJsZVxuXG4gICAgZnVuY3Rpb24gQ3JlYXRlQ29sdW1ucygpIHtcbiAgICAgICAgJHNjb3BlLmNvbHVtbnMgPSBbXTtcbiAgICAgICAgJHNjb3BlLm9yaWdpbmFsQ29sVmFscyA9IFtdO1xuICAgICAgICB2YXIgdGFibGUgPSAkc2NvcGUuc2luZ2xlVGFibGVbMF07XG5cblxuICAgICAgICBmb3IgKHZhciBwcm9wIGluIHRhYmxlKSB7XG4gICAgICAgICAgICBpZiAocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jykge1xuICAgICAgICAgICAgICAgICRzY29wZS5jb2x1bW5zLnB1c2gocHJvcCk7XG4gICAgICAgICAgICAgICAgJHNjb3BlLm9yaWdpbmFsQ29sVmFscy5wdXNoKHByb3ApO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgQ3JlYXRlQ29sdW1ucygpO1xuXG4gICAgZnVuY3Rpb24gY3JlYXRlVmlydHVhbENvbHVtbnMoKSB7XG4gICAgICAgIGlmICgkc2NvcGUuYXNzb2NpYXRpb25zLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgICRzY29wZS52aXJ0dWFsQ29sdW1ucyA9IFtdO1xuICAgICAgICAgICAgJHNjb3BlLmFzc29jaWF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChyb3cuVGFibGUxID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmIHJvdy5SZWxhdGlvbnNoaXAxID09PSAnaGFzTWFueScpIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHZpcnR1YWwgPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5uYW1lID0gcm93LkFsaWFzMTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHJvdy5UaHJvdWdoKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLnRhYmxlID0gcm93LlRocm91Z2g7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLmNvbHVtbmtleSA9IHJvdy5BbGlhczE7XG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLnRhYmxlID0gcm93LlRhYmxlMjtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwuY29sdW1ua2V5ID0gcm93LkFsaWFzMjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAkc2NvcGUudmlydHVhbENvbHVtbnMucHVzaCh2aXJ0dWFsKTtcbiAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKHJvdy5UYWJsZTIgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgcm93LlJlbGF0aW9uc2hpcDIgPT09ICdoYXNNYW55Jykge1xuICAgICAgICAgICAgICAgICAgICB2YXIgdmlydHVhbCA9IHt9O1xuICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLm5hbWUgPSByb3cuQWxpYXMyO1xuICAgICAgICAgICAgICAgICAgICBpZiAocm93LlRocm91Z2gpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwudGFibGUgPSByb3cuVGhyb3VnaDtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwuY29sdW1ua2V5ID0gcm93LkFsaWFzMjtcbiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwudGFibGUgPSByb3cuVGFibGUxO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5jb2x1bW5rZXkgPSByb3cuQWxpYXMxO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS52aXJ0dWFsQ29sdW1ucy5wdXNoKHZpcnR1YWwpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBjcmVhdGVWaXJ0dWFsQ29sdW1ucygpO1xuXG4gICAgLy90aGlzIGZ1bmN0aW9uIHdpbGwgcmUgcnVuIHdoZW4gdGhlIGZpbHRlciBmdW5jdGlvbiBpcyBpbnZva2VkLCBpbiBvcmRlciB0byByZXBvcHVsYXRlIHRoZSB0YWJsZVxuICAgIGZ1bmN0aW9uIENyZWF0ZVJvd3MoKSB7XG4gICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5ID0gW107XG4gICAgICAgICRzY29wZS5zaW5nbGVUYWJsZS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgdmFyIHJvd1ZhbHVlcyA9IFtdO1xuICAgICAgICAgICAgdmFyIHJvd09iaiA9IHt9O1xuXG4gICAgICAgICAgICBmb3IgKHZhciBwcm9wIGluIHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKSByb3dWYWx1ZXMucHVzaCh7XG4gICAgICAgICAgICAgICAgICAgIGNvbDogcHJvcCxcbiAgICAgICAgICAgICAgICAgICAgdmFsdWU6IHJvd1twcm9wXVxuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByb3dPYmoudmFsdWVzID0gcm93VmFsdWVzO1xuICAgICAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkucHVzaChyb3dPYmopO1xuICAgICAgICB9KVxuICAgIH1cblxuICAgIC8vIFNvcnQgdGhlIHZhbHVlcyBpbiBzaW5nbGVUYWJsZSBzbyB0aGF0IGFsbCB0aGUgdmFsdWVzIGZvciBhIGdpdmVuIHJvdyBhcmUgZ3JvdXBlZFxuICAgIENyZWF0ZVJvd3MoKTtcbiAgICAvL3NlbmRzIHRoZSBmaWx0ZXJpbmcgcXVlcnkgYW5kIHRoZW4gcmUgcmVuZGVycyB0aGUgdGFibGUgd2l0aCBmaWx0ZXJlZCBkYXRhXG4gICAgJHNjb3BlLmZpbHRlciA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCBkYXRhKSB7XG4gICAgICAgIFRhYmxlRmFjdG9yeS5maWx0ZXIoZGJOYW1lLCB0YWJsZU5hbWUsIGRhdGEpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQuZGF0YTtcbiAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICB9KVxuICAgIH1cblxuXG4gICAgJHNjb3BlLmNoZWNrRm9yZWlnbiA9IGZ1bmN0aW9uKGNvbCkge1xuICAgICAgICByZXR1cm4gJHNjb3BlLmZvcmVpZ25Db2xzLmhhc093blByb3BlcnR5KGNvbCk7XG4gICAgfVxuXG4gICAgJHNjb3BlLmZpbmRQcmltYXJ5ID0gVGFibGVGYWN0b3J5LmZpbmRQcmltYXJ5O1xuXG4gICAgLy8qKioqKioqKioqKiogSW1wb3J0YW50ICoqKioqKioqKlxuICAgIC8vIE1ha2Ugc3VyZSB0byB1cGRhdGUgdGhlIHJvdyB2YWx1ZXMgQkVGT1JFIHRoZSBjb2x1bW4gbmFtZVxuICAgIC8vIFRoZSByb3dWYWxzVG9VcGRhdGUgYXJyYXkgc3RvcmVzIHRoZSB2YWx1ZXMgb2YgdGhlIE9SSUdJTkFMIGNvbHVtbiBuYW1lcyBzbyBpZiB0aGUgY29sdW1uIG5hbWUgaXMgdXBkYXRlZCBhZnRlciB0aGUgcm93IHZhbHVlLCB3ZSBzdGlsbCBoYXZlIHJlZmVyZW5jZSB0byB3aGljaCBjb2x1bW4gdGhlIHJvdyB2YWx1ZSByZWZlcmVuY2VzXG5cblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9VcGRhdGluZyBDb2x1bW4gU3R1ZmYvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG5cbiAgICAkc2NvcGUuY29sVmFsc1RvVXBkYXRlID0gW107XG5cbiAgICAkc2NvcGUudXBkYXRlQ29sdW1ucyA9IGZ1bmN0aW9uKG9sZCwgbmV3Q29sTmFtZSwgaSkge1xuICAgICAgICAkc2NvcGUuY29sdW1uc1tpXSA9IG5ld0NvbE5hbWU7XG5cbiAgICAgICAgdmFyIGNvbE9iaiA9IHsgb2xkVmFsOiAkc2NvcGUub3JpZ2luYWxDb2xWYWxzW2ldLCBuZXdWYWw6IG5ld0NvbE5hbWUgfTtcblxuICAgICAgICAvLyBpZiB0aGVyZSBpcyBub3RoaW5nIGluIHRoZSBhcnJheSB0byB1cGRhdGUsIHB1c2ggdGhlIHVwZGF0ZSBpbnRvIGl0XG4gICAgICAgIGlmICgkc2NvcGUuY29sVmFsc1RvVXBkYXRlLmxlbmd0aCA9PT0gMCkgeyAkc2NvcGUuY29sVmFsc1RvVXBkYXRlLnB1c2goY29sT2JqKTsgfSBlbHNlIHtcbiAgICAgICAgICAgIGZvciAodmFyIGUgPSAwOyBlIDwgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZS5sZW5ndGg7IGUrKykge1xuICAgICAgICAgICAgICAgIGlmICgkc2NvcGUuY29sVmFsc1RvVXBkYXRlW2VdLm9sZFZhbCA9PT0gY29sT2JqLm9sZFZhbCkge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuY29sVmFsc1RvVXBkYXRlW2VdID0gY29sT2JqO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZS5wdXNoKGNvbE9iaik7XG4gICAgICAgIH1cbiAgICAgICAgLy8gY2hlY2sgdG8gc2VlIGlmIHRoZSByb3cgaXMgYWxyZWFkeSBzY2hlZHVsZWQgdG8gYmUgdXBkYXRlZCwgaWYgaXQgaXMsIHRoZW4gdXBkYXRlIGl0IHdpdGggdGhlIG5ldyB0aGluZyB0byBiZSB1cGRhdGVkXG4gICAgfVxuXG4gICAgLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1VwZGF0aW5nIFJvdyBTdHVmZi8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgICRzY29wZS5yb3dWYWxzVG9VcGRhdGUgPSBbXTtcblxuICAgICRzY29wZS51cGRhdGVSb3cgPSBmdW5jdGlvbihvbGQsIG5ld0NlbGwsIHJvdywgaSwgaikge1xuICAgICAgICByb3dbaV0gPSBuZXdDZWxsO1xuICAgICAgICB2YXIgcm93T2JqID0ge307XG4gICAgICAgIHZhciBjb2xzID0gJHNjb3BlLm9yaWdpbmFsQ29sVmFscztcbiAgICAgICAgZm9yICh2YXIgYyA9IDA7IGMgPCBjb2xzLmxlbmd0aDsgYysrKSB7XG4gICAgICAgICAgICB2YXIgY29sTmFtZSA9IGNvbHNbal07XG4gICAgICAgICAgICBpZihyb3dbY10gIT09IHVuZGVmaW5lZCkgcm93T2JqW2NvbE5hbWVdID0gcm93W2NdO1xuICAgICAgICAgICAgcm93T2JqWydpZCddID0gaTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIGlmIHRoZXJlIGlzIG5vdGhpbmcgaW4gdGhlIGFycmF5IHRvIHVwZGF0ZSwgcHVzaCB0aGUgdXBkYXRlIGludG8gaXRcbiAgICAgICAgaWYgKCRzY29wZS5yb3dWYWxzVG9VcGRhdGUubGVuZ3RoID09PSAwKSAkc2NvcGUucm93VmFsc1RvVXBkYXRlLnB1c2gocm93T2JqKTtcbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAvLyBjaGVjayB0byBzZWUgaWYgdGhlIHJvdyBpcyBhbHJlYWR5IHNjaGVkdWxlZCB0byBiZSB1cGRhdGVkLCBpZiBpdCBpcywgdGhlbiB1cGRhdGUgaXQgd2l0aCB0aGUgbmV3IHRoaW5nIHRvIGJlIHVwZGF0ZWRcbiAgICAgICAgICAgIGZvciAodmFyIGUgPSAwOyBlIDwgJHNjb3BlLnJvd1ZhbHNUb1VwZGF0ZS5sZW5ndGg7IGUrKykge1xuICAgICAgICAgICAgICAgIGlmICgkc2NvcGUucm93VmFsc1RvVXBkYXRlW2VdLmlkID09PSByb3dPYmpbJ2lkJ10pIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnJvd1ZhbHNUb1VwZGF0ZVtlXSA9IHJvd09iajtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgICRzY29wZS5yb3dWYWxzVG9VcGRhdGUucHVzaChyb3dPYmopO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLnVwZGF0ZUJhY2tlbmQgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIGRhdGEgPSB7IHJvd3M6ICRzY29wZS5yb3dWYWxzVG9VcGRhdGUsIGNvbHVtbnM6ICRzY29wZS5jb2xWYWxzVG9VcGRhdGUgfVxuICAgICAgICBUYWJsZUZhY3RvcnkudXBkYXRlQmFja2VuZCgkc2NvcGUudGhlRGJOYW1lLCAkc2NvcGUudGhlVGFibGVOYW1lLCBkYXRhKTtcbiAgICB9XG5cblxuICAgICRzY29wZS5kZWxldGVUYWJsZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgICBUYWJsZUZhY3RvcnkuZGVsZXRlVGFibGUoJHNjb3BlLmN1cnJlbnRUYWJsZSlcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnVGFibGUnLCB7IGRiTmFtZTogJHNjb3BlLnRoZURiTmFtZSB9LCB7IHJlbG9hZDogdHJ1ZSB9KVxuICAgICAgICAgICAgfSlcbiAgICB9XG5cbiAgICAvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vUXVlcnlpbmcgU3R1ZmYvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG5cbiAgICAkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zID0gW107XG5cbiAgICAkc2NvcGUudGFibGVzVG9RdWVyeSA9IFtdO1xuXG4gICAgYXNzb2NpYXRpb25zLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgIGlmIChyb3cuVGFibGUxID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMuaW5kZXhPZihyb3cuVGFibGUyKSA9PSAtMSkge1xuICAgICAgICAgICAgJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9ucy5wdXNoKHJvdy5UYWJsZTIpO1xuICAgICAgICB9IGVsc2UgaWYgKHJvdy5UYWJsZTIgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9ucy5pbmRleE9mKHJvdy5UYWJsZTEpID09IC0xKSB7XG4gICAgICAgICAgICAkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zLnB1c2gocm93LlRhYmxlMSk7XG4gICAgICAgIH1cbiAgICB9KVxuXG4gICAgJHNjb3BlLmdldEFzc29jaWF0ZWQgPSBmdW5jdGlvbih2YWwpIHtcbiAgICAgICAgaWYgKCRzY29wZS50YWJsZXNUb1F1ZXJ5LmluZGV4T2YoJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9uc1t2YWxdKSA9PT0gLTEpIHtcbiAgICAgICAgICAgICRzY29wZS50YWJsZXNUb1F1ZXJ5LnB1c2goJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9uc1t2YWxdKVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdmFyIGkgPSAkc2NvcGUudGFibGVzVG9RdWVyeS5pbmRleE9mKCRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnNbdmFsXSk7XG4gICAgICAgICAgICAkc2NvcGUudGFibGVzVG9RdWVyeS5zcGxpY2UoaSwgMSlcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS5jb2x1bW5zRm9yUXVlcnkgPSBbXTtcblxuICAgICRzY29wZS5nZXRDb2x1bW5zRm9yVGFibGUgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIHByb21pc2VzRm9yQ29sdW1ucyA9IFtdO1xuICAgICAgICAkc2NvcGUudGFibGVzVG9RdWVyeS5mb3JFYWNoKGZ1bmN0aW9uKHRhYmxlTmFtZSkge1xuICAgICAgICAgICAgcmV0dXJuIHByb21pc2VzRm9yQ29sdW1ucy5wdXNoKFRhYmxlRmFjdG9yeS5nZXRDb2x1bW5zRm9yVGFibGUoJHNjb3BlLnRoZURiTmFtZSwgdGFibGVOYW1lKSlcbiAgICAgICAgfSlcbiAgICAgICAgUHJvbWlzZS5hbGwocHJvbWlzZXNGb3JDb2x1bW5zKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oY29sdW1ucykge1xuICAgICAgICAgICAgICAgIGNvbHVtbnMuZm9yRWFjaChmdW5jdGlvbihjb2x1bW4pIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmNvbHVtbnNGb3JRdWVyeS5wdXNoKGNvbHVtbik7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS4kZXZhbEFzeW5jKClcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgfSlcblxuICAgIH1cblxuICAgIHZhciBzZWxlY3RlZENvbHVtbnMgPSB7fTtcbiAgICB2YXIgcXVlcnlUYWJsZTtcblxuICAgICRzY29wZS5nZXREYXRhRnJvbUNvbHVtbnMgPSBmdW5jdGlvbih2YWwpIHtcbiAgICAgICAgaWYoIXNlbGVjdGVkQ29sdW1ucykgc2VsZWN0ZWRDb2x1bW5zID0gW107XG5cbiAgICAgICAgdmFyIGNvbHVtbk5hbWUgPSAkc2NvcGUuY29sdW1uc0ZvclF1ZXJ5WzBdWydjb2x1bW5zJ11bdmFsLmldO1xuICAgICAgICB2YXIgdGFibGVOYW1lID0gdmFsLnRhYmxlTmFtZVxuICAgICAgICBxdWVyeVRhYmxlID0gdGFibGVOYW1lO1xuXG4gICAgICAgIGlmICghc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0pIHNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdID0gW107XG4gICAgICAgIGlmIChzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXS5pbmRleE9mKGNvbHVtbk5hbWUpICE9PSAtMSkge1xuICAgICAgICAgICAgc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0uc3BsaWNlKHNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdLmluZGV4T2YoY29sdW1uTmFtZSksIDEpXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXS5wdXNoKGNvbHVtbk5hbWUpO1xuICAgICAgICB9XG4gICAgICAgICRzY29wZS5zZWxlY3RlZENvbHVtbnMgPSBzZWxlY3RlZENvbHVtbnM7XG4gICAgfVxuXG5cbiAgICAvLyBSdW5uaW5nIHRoZSBxdWVyeSArIHJlbmRlcmluZyB0aGUgcXVlcnlcbiAgICAkc2NvcGUucmVzdWx0T2ZRdWVyeSA9IFtdO1xuXG4gICAgJHNjb3BlLnF1ZXJ5UmVzdWx0O1xuXG4gICAgJHNjb3BlLmFyciA9IFtdO1xuXG5cbiAgICAvLyB0aGVUYWJsZU5hbWVcblxuICAgICRzY29wZS5ydW5Kb2luID0gZnVuY3Rpb24oKSB7XG4gICAgICAgIC8vIGRiTmFtZSwgdGFibGUxLCBhcnJheU9mVGFibGVzLCBzZWxlY3RlZENvbHVtbnMsIGFzc29jaWF0aW9uc1xuICAgICAgICB2YXIgY29sdW1uc1RvUmV0dXJuID0gJHNjb3BlLmNvbHVtbnMubWFwKGZ1bmN0aW9uKGNvbE5hbWUpe1xuICAgICAgICAgICAgcmV0dXJuICRzY29wZS50aGVUYWJsZU5hbWUgKyAnLicgKyBjb2xOYW1lO1xuICAgICAgICB9KVxuICAgICAgICBmb3IodmFyIHByb3AgaW4gJHNjb3BlLnNlbGVjdGVkQ29sdW1ucyl7XG4gICAgICAgICAgICRzY29wZS5zZWxlY3RlZENvbHVtbnNbcHJvcF0uZm9yRWFjaChmdW5jdGlvbihjb2wpe1xuICAgICAgICAgICAgICAgIGNvbHVtbnNUb1JldHVybi5wdXNoKHByb3AgKyAnLicgKyBjb2wpXG4gICAgICAgICAgIH0pXG4gICAgICAgIH1cbiAgICAgICAgVGFibGVGYWN0b3J5LnJ1bkpvaW4oJHNjb3BlLnRoZURiTmFtZSwgJHNjb3BlLnRoZVRhYmxlTmFtZSwgJHNjb3BlLnRhYmxlc1RvUXVlcnksICRzY29wZS5zZWxlY3RlZENvbHVtbnMsICRzY29wZS5hc3NvY2lhdGlvbnMsIGNvbHVtbnNUb1JldHVybilcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHF1ZXJ5UmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnF1ZXJ5UmVzdWx0ID0gcXVlcnlSZXN1bHQ7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgJHN0YXRlLmdvKCdUYWJsZS5TaW5nbGUucXVlcnknKTtcbiAgICAgICAgICAgIH0pXG4gICAgfVxuXG4gICAgJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkID0gdHJ1ZTtcblxuICAgICRzY29wZS5vcGVuID0gZnVuY3Rpb24gKGRiTmFtZSwgdGJsTmFtZSwgY29sLCBpbmRleCkge1xuXG4gICAgICB2YXIgbW9kYWxJbnN0YW5jZSA9ICR1aWJNb2RhbC5vcGVuKHtcbiAgICAgICAgYW5pbWF0aW9uOiAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvYXNzb2NpYXRpb24ubW9kYWwuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdBc3NvY2lhdGlvbkluc3RhbmNlQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICBmb3JlaWduQ29sczogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuICRzY29wZS5mb3JlaWduQ29scztcbiAgICAgICAgICB9LFxuICAgICAgICAgIGZvclRhYmxlOiBmdW5jdGlvbihUYWJsZUZhY3Rvcnkpe1xuICAgICAgICAgICAgY29uc29sZS5sb2codGJsTmFtZSlcbiAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZmluZFByaW1hcnkoZGJOYW1lLCB0YmxOYW1lKTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIGZvclRhYmxlTmFtZTogZnVuY3Rpb24oKXtcbiAgICAgICAgICAgIHJldHVybiB0YmxOYW1lO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgY3VyclRhYmxlOiBmdW5jdGlvbigpe1xuICAgICAgICAgICAgcmV0dXJuICRzY29wZS50aGVUYWJsZU5hbWVcbiAgICAgICAgICB9LFxuICAgICAgICAgIGNvbE5hbWU6IGZ1bmN0aW9uICgpe1xuICAgICAgICAgICAgcmV0dXJuIGNvbDtcbiAgICAgICAgICB9LFxuICAgICAgICAgIGlkMTogZnVuY3Rpb24oKXtcbiAgICAgICAgICAgIHJldHVybiBpbmRleDtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH0pO1xuXG4gICAgICBtb2RhbEluc3RhbmNlLnJlc3VsdC50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgY29uc29sZS5sb2coXCJDTE9TRURcIilcbiAgICAgICAgJHNjb3BlLiRldmFsQXN5bmMoKTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICAkc2NvcGUudG9nZ2xlQW5pbWF0aW9uID0gZnVuY3Rpb24gKCkge1xuICAgICAgJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkID0gISRzY29wZS5hbmltYXRpb25zRW5hYmxlZDtcbiAgICB9O1xuXG59KTtcbiIsImFwcC5jb250cm9sbGVyKCdUYWJsZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBhbGxUYWJsZXMsICRzdGF0ZSwgVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMsICR1aWJNb2RhbCwgSG9tZUZhY3RvcnksIGFzc29jaWF0aW9ucywgYWxsQ29sdW1ucykge1xuXG5cdCRzY29wZS5hbGxUYWJsZXMgPSBhbGxUYWJsZXM7XG5cblx0JHNjb3BlLmNvbHVtbkFycmF5ID0gW107XG5cblx0JHNjb3BlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWVcblxuXHQkc2NvcGUuYXNzb2NpYXRpb25zID0gYXNzb2NpYXRpb25zO1xuXG5cdCRzY29wZS5hbGxDb2x1bW5zID0gYWxsQ29sdW1ucztcblxuXHQkc2NvcGUuYXNzb2NpYXRpb25UYWJsZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWUgKyAnX2Fzc29jJztcblxuXHQkc2NvcGUubnVtVGFibGVzID0gJHNjb3BlLmFsbFRhYmxlcy5yb3dzLmxlbmd0aDtcblxuXHQkc2NvcGUuYWRkID0gZnVuY3Rpb24oKSB7XG5cdFx0JHNjb3BlLmNvbHVtbkFycmF5LnB1c2goJzEnKTtcblx0fVxuXG5cdCRzY29wZS4kc3RhdGUgPSAkc3RhdGU7IFx0Ly8gdXNlZCB0byBoaWRlIHRoZSBsaXN0IG9mIGFsbCB0YWJsZXMgd2hlbiBpbiBzaW5nbGUgdGFibGUgc3RhdGVcblxuXHQkc2NvcGUuYXNzb2NpYXRpb25UeXBlcyA9IFsnaGFzT25lJywgJ2hhc01hbnknXTtcblxuXHQkc2NvcGUuZGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZTtcblxuXHQkc2NvcGUubWFrZUFzc29jaWF0aW9ucyA9IFRhYmxlRmFjdG9yeS5tYWtlQXNzb2NpYXRpb25zO1xuXG5cdCRzY29wZS53aGVyZWJldHdlZW4gPSBmdW5jdGlvbihjb25kaXRpb24pIHtcblx0XHRpZihjb25kaXRpb24gPT09IFwiV0hFUkUgQkVUV0VFTlwiIHx8IGNvbmRpdGlvbiA9PT0gXCJXSEVSRSBOT1QgQkVUV0VFTlwiKSByZXR1cm4gdHJ1ZTtcblx0fVxuXG5cdCRzY29wZS5jcmVhdGVUYWJsZSA9IGZ1bmN0aW9uKHRhYmxlKXtcblx0XHRUYWJsZUZhY3RvcnkuY3JlYXRlVGFibGUodGFibGUpXG5cdFx0LnRoZW4oZnVuY3Rpb24oKXtcblx0XHRcdCRzdGF0ZS5nbygnVGFibGUnLCB7ZGJOYW1lOiRzY29wZS5kYk5hbWV9KTtcblx0XHR9KVxuXHR9XG5cblx0JHNjb3BlLmNvbHVtbkRhdGFUeXBlID0gZnVuY3Rpb24oKSB7XG5cdFx0JHNjb3BlLmFsbENvbHVtbnMuZm9yRWFjaChmdW5jdGlvbihvYmopIHtcblx0XHRcdGlmKG9iai50YWJsZV9uYW1lID09PSAkc2NvcGUucXVlcnkudGFibGUxICYmIG9iai5jb2x1bW5fbmFtZSA9PT0gJHNjb3BlLnF1ZXJ5LmNvbHVtbikgJHNjb3BlLnR5cGUgPSBvYmouZGF0YV90eXBlO1xuXHRcdH0pXG5cdH1cblxuXHQkc2NvcGUuc2VsZWN0ZWRBc3NvYyA9IHt9O1xuXG5cdC8vICRzY29wZS5nZXRBc3NvY2lhdGVkID0gZnVuY3Rpb24odGFibGVOYW1lKSB7XG5cdC8vIFx0JHNjb3BlLmFzc29jaWF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHJvdyl7XG5cdC8vIFx0XHRpZighJHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXSl7IFxuXHQvLyBcdFx0XHQkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdID0gW107XG5cdC8vIFx0XHR9XG5cdC8vIFx0XHRpZihyb3cuVGFibGUxID09PSB0YWJsZU5hbWUgJiYgJHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXS5pbmRleE9mKHJvdy5UYWJsZTIpID09IC0xKXtcblx0Ly8gXHRcdFx0JHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXS5wdXNoKHJvdy5UYWJsZTIpO1xuXHQvLyBcdFx0fVxuXHQvLyBcdFx0ZWxzZSBpZihyb3cuVGFibGUyID09PSB0YWJsZU5hbWUgJiYgJHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXS5pbmRleE9mKHJvdy5UYWJsZTEpID09IC0xKXtcblx0Ly8gXHRcdFx0JHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXS5wdXNoKHJvdy5UYWJsZTEpO1x0XG5cdC8vIFx0XHR9IFxuXHQvLyBcdH0pXG5cdC8vIH1cblxuXHQvLyAkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zID0gW107XG5cblx0Ly8gYXNzb2NpYXRpb25zLmZvckVhY2goZnVuY3Rpb24ocm93KXtcblx0Ly8gXHRpZihyb3cuVGFibGUxID09PSB0YWJsZU5hbWUgJiYgJHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXS5pbmRleE9mKHJvdy5UYWJsZTIpID09IC0xKXtcblx0Ly8gXHRcdCRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMucHVzaChyb3cuVGFibGUyKTtcblx0Ly8gXHR9XG5cdC8vIFx0ZWxzZSBpZihyb3cuVGFibGUyID09PSB0YWJsZU5hbWUgJiYgJHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXS5pbmRleE9mKHJvdy5UYWJsZTEpID09IC0xKXtcblx0Ly8gXHRcdCRzY29wZS5zZWxlY3RlZEFzc29jW3RhYmxlTmFtZV0ucHVzaChyb3cuVGFibGUxKTtcdFxuXHQvLyBcdH0gXG5cdC8vIH0pXG5cblx0JHNjb3BlLnN1Ym1pdFF1ZXJ5ID0gVGFibGVGYWN0b3J5LnN1Ym1pdFF1ZXJ5O1xuXG59KTtcbiIsImFwcC5mYWN0b3J5KCdUYWJsZUZhY3RvcnknLCBmdW5jdGlvbiAoJGh0dHAsICRzdGF0ZVBhcmFtcykge1xuXG5cdHZhciBUYWJsZUZhY3RvcnkgPSB7fTtcblxuXHRmdW5jdGlvbiByZXNUb0RhdGEocmVzKSB7XG4gICAgICAgIHJldHVybiByZXMuZGF0YTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZ2V0QWxsVGFibGVzID0gZnVuY3Rpb24oZGJOYW1lKXtcbiAgICBcdHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSlcbiAgICBcdC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZ2V0U2luZ2xlVGFibGUgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXREYk5hbWUgPSBmdW5jdGlvbihkYk5hbWUpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL21hc3RlcmRiLycgKyBkYk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZmlsdGVyID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIGRhdGEpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLnB1dCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lICsgJy9maWx0ZXInLCBkYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS51cGRhdGVCYWNrZW5kID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIGRhdGEpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLnB1dCgnYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUsIGRhdGEpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmFkZFJvdyA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCByb3dOdW1iZXIpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJ2FwaS9jbGllbnRkYi9hZGRyb3cvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSwge3Jvd051bWJlcjogcm93TnVtYmVyfSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkucmVtb3ZlUm93ID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIHJvd0lkKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmRlbGV0ZSgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lICsgJy8nICsgcm93SWQpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkucmVtb3ZlQ29sdW1uID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIGNvbHVtbk5hbWUpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnL2NvbHVtbi8nICsgY29sdW1uTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5hZGRDb2x1bW4gPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgbnVtTmV3Q29sKXtcbiAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJ2FwaS9jbGllbnRkYi9hZGRjb2x1bW4vJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSArICcvJyArIG51bU5ld0NvbClcbiAgICB9XG4gICAgVGFibGVGYWN0b3J5LmNyZWF0ZVRhYmxlID0gZnVuY3Rpb24odGFibGUpe1xuICAgICAgICB0YWJsZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lO1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL2FwaS9jbGllbnRkYicsIHRhYmxlKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5kZWxldGVUYWJsZSA9IGZ1bmN0aW9uKGN1cnJlbnRUYWJsZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL2NsaWVudGRiLycgKyBjdXJyZW50VGFibGUuZGJOYW1lICsgJy8nICsgY3VycmVudFRhYmxlLnRhYmxlTmFtZSlcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkubWFrZUFzc29jaWF0aW9ucyA9IGZ1bmN0aW9uKGFzc29jaWF0aW9uLCBkYk5hbWUpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvYXNzb2NpYXRpb24nLCBhc3NvY2lhdGlvbilcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZGVsZXRlRGIgPSBmdW5jdGlvbihkYk5hbWUpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmRlbGV0ZSgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRBc3NvY2lhdGlvbnMgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2NsaWVudGRiL2Fzc29jaWF0aW9udGFibGUvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICAgVGFibGVGYWN0b3J5LmdldEFsbEFzc29jaWF0aW9ucyA9IGZ1bmN0aW9uKGRiTmFtZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2NsaWVudGRiL2FsbGFzc29jaWF0aW9ucy8nICsgZGJOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRBbGxDb2x1bW5zID0gZnVuY3Rpb24oZGJOYW1lKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvZ2V0YWxsY29sdW1ucy8nICsgZGJOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRDb2x1bW5zRm9yVGFibGUgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvY29sdW1uc2ZvcnRhYmxlLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LnJ1bkpvaW4gPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlMSwgYXJyYXlPZlRhYmxlcywgc2VsZWN0ZWRDb2x1bW5zLCBhc3NvY2lhdGlvbnMsIGNvbHNUb1JldHVybikge1xuICAgICAgICB2YXIgZGF0YSA9IHt9O1xuICAgICAgICBkYXRhLmRiTmFtZSA9IGRiTmFtZTtcbiAgICAgICAgZGF0YS50YWJsZTIgPSBhcnJheU9mVGFibGVzWzBdO1xuICAgICAgICBkYXRhLmFycmF5T2ZUYWJsZXMgPSBhcnJheU9mVGFibGVzO1xuICAgICAgICBkYXRhLnNlbGVjdGVkQ29sdW1ucyA9IHNlbGVjdGVkQ29sdW1ucztcbiAgICAgICAgZGF0YS5jb2xzVG9SZXR1cm4gPSBjb2xzVG9SZXR1cm47XG5cbiAgICAgICAgLy8gW2hhc01hbnksIGhhc09uZSwgaGFzTWFueSBwcmltYXJ5IGtleSwgaGFzT25lIGZvcmdlaW4ga2V5XVxuXG4gICAgICAgIGFzc29jaWF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgaWYocm93LlRhYmxlMSA9PT0gdGFibGUxICYmIHJvdy5UYWJsZTIgPT09IGRhdGEudGFibGUyKXtcbiAgICAgICAgICAgICAgICBkYXRhLmFsaWFzID0gcm93LkFsaWFzMTtcbiAgICAgICAgICAgICAgICBpZihyb3cuUmVsYXRpb25zaGlwMSA9PT0gJ2hhc09uZScpe1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMSA9IHJvdy5UYWJsZTI7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUyID0gcm93LlRhYmxlMTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZXtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTEgPSByb3cuVGFibGUxO1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMiA9IHJvdy5UYWJsZTI7ICAgXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSBpZihyb3cuVGFibGUxID09PSBkYXRhLnRhYmxlMiAmJiByb3cuVGFibGUyID09PSB0YWJsZTEpe1xuICAgICAgICAgICAgICAgIGRhdGEuYWxpYXMgPSByb3cuQWxpYXMxO1xuICAgICAgICAgICAgICAgIGlmKHJvdy5SZWxhdGlvbnNoaXAxID09PSAnaGFzTWFueScpe1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMSA9IHJvdy5UYWJsZTE7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUyID0gcm93LlRhYmxlMjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZXtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTEgPSByb3cuVGFibGUyO1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMiA9IHJvdy5UYWJsZTE7ICAgXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9KVxuXG4gICAgICAgIHJldHVybiAkaHR0cC5wdXQoJy9hcGkvY2xpZW50ZGIvcnVuam9pbicsIGRhdGEpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldFByaW1hcnlLZXlzID0gZnVuY3Rpb24oaWQsIGRiTmFtZSwgdGFibGVOYW1lLCBjb2x1bW5rZXkpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnLycgKyBpZCArIFwiL1wiICsgY29sdW1ua2V5KVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5maW5kUHJpbWFyeSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGJsTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvcHJpbWFyeS8nK2RiTmFtZSsnLycrdGJsTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3Rvcnkuc2V0Rm9yZWlnbktleSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGJsTmFtZSwgY29sTmFtZSwgaWQxLCBpZDIpe1xuICAgICAgICB2YXIgZGF0YSA9IHt9O1xuICAgICAgICBkYXRhLmRiTmFtZSA9IGRiTmFtZTtcbiAgICAgICAgZGF0YS50YmxOYW1lID0gdGJsTmFtZTtcbiAgICAgICAgZGF0YS5jb2xOYW1lID0gY29sTmFtZTtcbiAgICAgICAgZGF0YS5pZDEgPSBpZDE7XG4gICAgICAgIGRhdGEuaWQyID0gaWQyO1xuXG4gICAgICAgIHJldHVybiAkaHR0cC5wdXQoJy9hcGkvY2xpZW50ZGIvc2V0Rm9yZWlnbktleScsIGRhdGEpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7ICAgXG4gICAgfVxuXG5cdHJldHVybiBUYWJsZUZhY3Rvcnk7IFxufSkiLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZScsIHtcbiAgICAgICAgdXJsOiAnLzpkYk5hbWUnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL3RhYmxlLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVGFibGVDdHJsJyxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICBcdGFsbFRhYmxlczogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldEFsbFRhYmxlcygkc3RhdGVQYXJhbXMuZGJOYW1lKTtcbiAgICAgICAgXHR9LCBcbiAgICAgICAgICAgIGFzc29jaWF0aW9uczogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldEFsbEFzc29jaWF0aW9ucygkc3RhdGVQYXJhbXMuZGJOYW1lKTtcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBhbGxDb2x1bW5zOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0QWxsQ29sdW1ucygkc3RhdGVQYXJhbXMuZGJOYW1lKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pO1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlLlNpbmdsZScsIHtcbiAgICAgICAgdXJsOiAnLzp0YWJsZU5hbWUnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL3NpbmdsZXRhYmxlLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnU2luZ2xlVGFibGVDdHJsJyxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICAgICAgc2luZ2xlVGFibGU6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSgkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKTtcbiAgICAgICAgICAgIH0sIFxuICAgICAgICAgICAgYXNzb2NpYXRpb25zOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0QXNzb2NpYXRpb25zKCRzdGF0ZVBhcmFtcy5kYk5hbWUsICRzdGF0ZVBhcmFtcy50YWJsZU5hbWUpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSk7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUuSm9pbicsIHtcbiAgICAgICAgdXJsOiAnLzp0YWJsZU5hbWUvOnJvd0lkLzprZXkvam9pbicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvam9pbi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0pvaW5UYWJsZUN0cmwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgICBqb2luVGFibGU6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRQcmltYXJ5S2V5cygkc3RhdGVQYXJhbXMucm93SWQsICRzdGF0ZVBhcmFtcy5kYk5hbWUsICRzdGF0ZVBhcmFtcy50YWJsZU5hbWUsICRzdGF0ZVBhcmFtcy5rZXkpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSk7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUuY3JlYXRlJywge1xuICAgICAgICB1cmw6ICcvY3JlYXRldGFibGUnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL2NyZWF0ZXRhYmxlLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVGFibGVDdHJsJ1xuICAgIH0pO1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlLnNldEFzc29jaWF0aW9uJywge1xuICAgICAgICB1cmw6ICcvc2V0YXNzb2NpYXRpb24nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL3NldGFzc29jaWF0aW9uLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVGFibGVDdHJsJ1xuICAgIH0pO1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlLlNpbmdsZS5xdWVyeScsIHtcbiAgICAgICAgdXJsOiAnL3F1ZXJ5cmVzdWx0JyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9xdWVyeS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1NpbmdsZVRhYmxlQ3RybCdcbiAgICB9KTsgICAgIFxuXG59KTsiLCJhcHAuZmFjdG9yeSgnRnVsbHN0YWNrUGljcycsIGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4gW1xuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I3Z0JYdWxDQUFBWFFjRS5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9mYmNkbi1zcGhvdG9zLWMtYS5ha2FtYWloZC5uZXQvaHBob3Rvcy1hay14YXAxL3QzMS4wLTgvMTA4NjI0NTFfMTAyMDU2MjI5OTAzNTkyNDFfODAyNzE2ODg0MzMxMjg0MTEzN19vLmpwZycsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQi1MS1VzaElnQUV5OVNLLmpwZycsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQjc5LVg3b0NNQUFrdzd5LmpwZycsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQi1VajlDT0lJQUlGQWgwLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQjZ5SXlGaUNFQUFxbDEyLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0UtVDc1bFdBQUFtcXFKLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0V2WkFnLVZBQUFrOTMyLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0VnTk1lT1hJQUlmRGhLLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0VReUlETldnQUF1NjBCLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0NGM1Q1UVc4QUUybEdKLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0FlVnc1U1dvQUFBTHNqLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0FhSklQN1VrQUFsSUdzLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0FRT3c5bFdFQUFZOUZsLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQi1PUWJWckNNQUFOd0lNLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQjliX2Vyd0NZQUF3UmNKLnBuZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQjVQVGR2bkNjQUVBbDR4LmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQjRxd0MwaUNZQUFsUEdoLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQjJiMzN2UklVQUE5bzFELmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQndwSXdyMUlVQUF2TzJfLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQnNTc2VBTkNZQUVPaEx3LmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0o0dkxmdVV3QUFkYTRMLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0k3d3pqRVZFQUFPUHBTLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0lkSHZUMlVzQUFubkhWLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0dDaVBfWVdZQUFvNzVWLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0lTNEpQSVdJQUkzN3F1LmpwZzpsYXJnZSdcbiAgICBdO1xufSk7XG4iLCJhcHAuZmFjdG9yeSgnUmFuZG9tR3JlZXRpbmdzJywgZnVuY3Rpb24gKCkge1xuXG4gICAgdmFyIGdldFJhbmRvbUZyb21BcnJheSA9IGZ1bmN0aW9uIChhcnIpIHtcbiAgICAgICAgcmV0dXJuIGFycltNYXRoLmZsb29yKE1hdGgucmFuZG9tKCkgKiBhcnIubGVuZ3RoKV07XG4gICAgfTtcblxuICAgIHZhciBncmVldGluZ3MgPSBbXG4gICAgICAgICdIZWxsbywgd29ybGQhJyxcbiAgICAgICAgJ0F0IGxvbmcgbGFzdCwgSSBsaXZlIScsXG4gICAgICAgICdIZWxsbywgc2ltcGxlIGh1bWFuLicsXG4gICAgICAgICdXaGF0IGEgYmVhdXRpZnVsIGRheSEnLFxuICAgICAgICAnSVxcJ20gbGlrZSBhbnkgb3RoZXIgcHJvamVjdCwgZXhjZXB0IHRoYXQgSSBhbSB5b3Vycy4gOiknLFxuICAgICAgICAnVGhpcyBlbXB0eSBzdHJpbmcgaXMgZm9yIExpbmRzYXkgTGV2aW5lLicsXG4gICAgICAgICfjgZPjgpPjgavjgaHjga/jgIHjg6bjg7zjgrbjg7zmp5jjgIInLFxuICAgICAgICAnV2VsY29tZS4gVG8uIFdFQlNJVEUuJyxcbiAgICAgICAgJzpEJyxcbiAgICAgICAgJ1llcywgSSB0aGluayB3ZVxcJ3ZlIG1ldCBiZWZvcmUuJyxcbiAgICAgICAgJ0dpbW1lIDMgbWlucy4uLiBJIGp1c3QgZ3JhYmJlZCB0aGlzIHJlYWxseSBkb3BlIGZyaXR0YXRhJyxcbiAgICAgICAgJ0lmIENvb3BlciBjb3VsZCBvZmZlciBvbmx5IG9uZSBwaWVjZSBvZiBhZHZpY2UsIGl0IHdvdWxkIGJlIHRvIG5ldlNRVUlSUkVMIScsXG4gICAgXTtcblxuICAgIHJldHVybiB7XG4gICAgICAgIGdyZWV0aW5nczogZ3JlZXRpbmdzLFxuICAgICAgICBnZXRSYW5kb21HcmVldGluZzogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuIGdldFJhbmRvbUZyb21BcnJheShncmVldGluZ3MpO1xuICAgICAgICB9XG4gICAgfTtcblxufSk7XG4iLCJhcHAuZGlyZWN0aXZlKCdmdWxsc3RhY2tMb2dvJywgZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiB7XG4gICAgICAgIHJlc3RyaWN0OiAnRScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvY29tbW9uL2RpcmVjdGl2ZXMvZnVsbHN0YWNrLWxvZ28vZnVsbHN0YWNrLWxvZ28uaHRtbCdcbiAgICB9O1xufSk7IiwiYXBwLmRpcmVjdGl2ZSgnc2lkZWJhcicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBdXRoU2VydmljZSwgQVVUSF9FVkVOVFMsICRzdGF0ZSkge1xuXG4gICAgcmV0dXJuIHtcbiAgICAgICAgcmVzdHJpY3Q6ICdFJyxcbiAgICAgICAgc2NvcGU6IHt9LFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL25hdmJhci9uYXZiYXIuaHRtbCcsXG4gICAgICAgIGxpbms6IGZ1bmN0aW9uIChzY29wZSkge1xuXG4gICAgICAgICAgICBzY29wZS5pdGVtcyA9IFtcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnSG9tZScsIHN0YXRlOiAnaG9tZScgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnQWJvdXQnLCBzdGF0ZTogJ2Fib3V0JyB9LFxuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdEb2N1bWVudGF0aW9uJywgc3RhdGU6ICdkb2NzJyB9LFxuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdNZW1iZXJzIE9ubHknLCBzdGF0ZTogJ21lbWJlcnNPbmx5JywgYXV0aDogdHJ1ZSB9XG4gICAgICAgICAgICBdO1xuXG4gICAgICAgICAgICBzY29wZS51c2VyID0gbnVsbDtcblxuICAgICAgICAgICAgc2NvcGUuaXNMb2dnZWRJbiA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gQXV0aFNlcnZpY2UuaXNBdXRoZW50aWNhdGVkKCk7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICBzY29wZS5sb2dvdXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgQXV0aFNlcnZpY2UubG9nb3V0KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgJHN0YXRlLmdvKCdsYW5kaW5nUGFnZScpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgdmFyIHNldFVzZXIgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCkudGhlbihmdW5jdGlvbiAodXNlcikge1xuICAgICAgICAgICAgICAgICAgICBzY29wZS51c2VyID0gdXNlcjtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHZhciByZW1vdmVVc2VyID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHNjb3BlLnVzZXIgPSBudWxsO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgc2V0VXNlcigpO1xuXG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5sb2dpblN1Y2Nlc3MsIHNldFVzZXIpO1xuICAgICAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMubG9nb3V0U3VjY2VzcywgcmVtb3ZlVXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5zZXNzaW9uVGltZW91dCwgcmVtb3ZlVXNlcik7XG5cbiAgICAgICAgfVxuXG4gICAgfTtcblxufSk7XG4iLCJhcHAuZGlyZWN0aXZlKCdyYW5kb0dyZWV0aW5nJywgZnVuY3Rpb24gKFJhbmRvbUdyZWV0aW5ncykge1xuXG4gICAgcmV0dXJuIHtcbiAgICAgICAgcmVzdHJpY3Q6ICdFJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9yYW5kby1ncmVldGluZy9yYW5kby1ncmVldGluZy5odG1sJyxcbiAgICAgICAgbGluazogZnVuY3Rpb24gKHNjb3BlKSB7XG4gICAgICAgICAgICBzY29wZS5ncmVldGluZyA9IFJhbmRvbUdyZWV0aW5ncy5nZXRSYW5kb21HcmVldGluZygpO1xuICAgICAgICB9XG4gICAgfTtcblxufSk7Il0sInNvdXJjZVJvb3QiOiIvc291cmNlLyJ9
