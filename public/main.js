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
app.config(function ($stateProvider) {
    $stateProvider.state('docs', {
        url: '/docs',
        templateUrl: 'js/docs/docs.html'
    });
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

    $scope.qFilter = function (referenceString, val) {
        if (!referenceString) return true;else {
            for (var prop in val) {
                var cellVal = val[prop].toString().toLowerCase();
                var searchVal = referenceString.toString().toLowerCase();
                console.log(cellVal, searchVal, cellVal.indexOf(searchVal) !== -1);
                if (cellVal.indexOf(searchVal) !== -1) return true;
            }
        }
        return false;
    };
});
app.controller('SingleTableCtrl', function ($scope, TableFactory, $stateParams, singleTable, $window, $state, $uibModal, associations, $log) {

    ///////////////////////////////Putting stuff on scope/////////////////////////////////////////////////

    $scope.theDbName = $stateParams.dbName;
    $scope.theTableName = $stateParams.tableName;
    $scope.singleTable = singleTable[0].sort(function (a, b) {
        if (a.id > b.id) return 1;
        if (a.id < b.id) return -1;
        return 0;
    });
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
        for (var i = instanceArray.length - 1; i >= 0; i--) {
            var row = instanceArray[i];
            var length = i;
            console.log(row);
            if (row.selected) {
                TableFactory.removeRow(db, table, row['values'][0]['value'], length).then(function (result) {
                    $scope.singleTable = result;
                    CreateRows();
                });
            }
        }
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

    $scope.removeRow = function (db, table, row, instanceArray) {
        var length = instanceArray.length - 1;
        TableFactory.removeRow(db, table, row, length).then(function (result) {
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
        var cols = $scope.originalColVals;
        var found = false;
        var colName = cols[j];
        for (var k = 0; k < $scope.rowValsToUpdate.length; k++) {
            var obj = $scope.rowValsToUpdate[k];
            console.log(obj);
            if (obj['id'] === i) {
                found = true;
                if (obj[colName]) obj[colName] = newCell;
                obj[colName] = newCell;
            }
        }
        if (!found) {
            var rowObj = {};
            rowObj['id'] = i;
            rowObj[colName] = newCell;
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
            backdrop: false,
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

    $scope.filteredRows = [];
    $scope.currentPage = 1;
    $scope.numPerPage = 10;
    $scope.maxSize = 5;

    $scope.$watch("currentPage + numPerPage", function () {
        var begin = ($scope.currentPage - 1) * $scope.numPerPage;
        var end = begin + $scope.numPerPage;
        $scope.filteredRows = $scope.instanceArray.slice(begin, end);
    });

    $scope.$watch("instanceArray", function () {
        var begin = ($scope.currentPage - 1) * $scope.numPerPage;
        var end = begin + $scope.numPerPage;
        $scope.filteredRows = $scope.instanceArray.slice(begin, end);
    });
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

    $scope.submitted = false;

    $scope.makeAssociations = function (association, dbName) {
        $scope.submitted = true;
        TableFactory.makeAssociations(association, dbName);
        // .then(function() {
        // 	$state.go('Table', {dbName : $scope.dbName}, {reload:true});
        // })
    };

    $scope.wherebetween = function (condition) {
        if (condition === "WHERE BETWEEN" || condition === "WHERE NOT BETWEEN") return true;
    };

    $scope.createTable = function (table) {
        TableFactory.createTable(table).then(function () {
            $state.go('Table', { dbName: $scope.dbName }, { reload: true });
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

    TableFactory.removeRow = function (dbName, tableName, rowId, length) {
        return $http.delete('/api/clientdb/' + dbName + '/' + tableName + '/' + rowId + '/' + length).then(resToData);
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
        controller: 'QueryTableCtrl'
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

app.directive('fullstackLogo', function () {
    return {
        restrict: 'E',
        templateUrl: 'js/common/directives/fullstack-logo/fullstack-logo.html'
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcC5qcyIsImFib3V0L2Fib3V0LmpzIiwiZG9jcy9kb2NzLmpzIiwiY3JlYXRlREIvY3JlYXRlREIuY29udHJvbGxlci5qcyIsImNyZWF0ZURCL2NyZWF0ZURCLmZhY3RvcnkuanMiLCJjcmVhdGVEQi9jcmVhdGVEQi5zdGF0ZS5qcyIsImZzYS9mc2EtcHJlLWJ1aWx0LmpzIiwiaG9tZS9ob21lLmNvbnRyb2xsZXIuanMiLCJob21lL2hvbWUuZmFjdG9yeS5qcyIsImhvbWUvaG9tZS5zdGF0ZS5qcyIsImxhbmRpbmdQYWdlL2xhbmRpbmdQYWdlLnN0YXRlLmpzIiwibG9naW4vbG9naW4uanMiLCJtZW1iZXJzLW9ubHkvbWVtYmVycy1vbmx5LmpzIiwib2F1dGgvb2F1dGgtYnV0dG9uLmRpcmVjdGl2ZS5qcyIsInNpZ251cC9zaWdudXAuanMiLCJ0YWJsZS9hc3NvY2lhdGlvbi5jb250cm9sbGVyLmpzIiwidGFibGUvZGVsZXRlREJNb2RhbC5qcyIsInRhYmxlL2RlbGV0ZVRhYmxlTW9kYWwuanMiLCJ0YWJsZS9qb2luLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS9xdWVyeS5jb250cm9sbGVyLmpzIiwidGFibGUvc2luZ2xldGFibGUuY29udHJvbGxlci5qcyIsInRhYmxlL3RhYmxlLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS90YWJsZS5mYWN0b3J5LmpzIiwidGFibGUvdGFibGUuc3RhdGUuanMiLCJjb21tb24vZmFjdG9yaWVzL0Z1bGxzdGFja1BpY3MuanMiLCJjb21tb24vZmFjdG9yaWVzL1JhbmRvbUdyZWV0aW5ncy5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL25hdmJhci9uYXZiYXIuanMiLCJjb21tb24vZGlyZWN0aXZlcy9mdWxsc3RhY2stbG9nby9mdWxsc3RhY2stbG9nby5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL3JhbmRvLWdyZWV0aW5nL3JhbmRvLWdyZWV0aW5nLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOztBQUNBLE9BQUEsR0FBQSxHQUFBLFFBQUEsTUFBQSxDQUFBLHVCQUFBLEVBQUEsQ0FBQSxhQUFBLEVBQUEsV0FBQSxFQUFBLGNBQUEsRUFBQSxXQUFBLENBQUEsQ0FBQTs7QUFFQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGtCQUFBLEVBQUEsaUJBQUEsRUFBQTs7QUFFQSxzQkFBQSxTQUFBLENBQUEsSUFBQTs7QUFFQSx1QkFBQSxTQUFBLENBQUEsR0FBQTs7QUFFQSx1QkFBQSxJQUFBLENBQUEsaUJBQUEsRUFBQSxZQUFBO0FBQ0EsZUFBQSxRQUFBLENBQUEsTUFBQTtBQUNBLEtBRkE7QUFHQSxDQVRBOzs7QUFZQSxJQUFBLEdBQUEsQ0FBQSxVQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUEsTUFBQSxFQUFBOzs7QUFHQSxRQUFBLCtCQUFBLFNBQUEsNEJBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxJQUFBLE1BQUEsSUFBQSxDQUFBLFlBQUE7QUFDQSxLQUZBOzs7O0FBTUEsZUFBQSxHQUFBLENBQUEsbUJBQUEsRUFBQSxVQUFBLEtBQUEsRUFBQSxPQUFBLEVBQUEsUUFBQSxFQUFBOztBQUVBLFlBQUEsQ0FBQSw2QkFBQSxPQUFBLENBQUEsRUFBQTs7O0FBR0E7QUFDQTs7QUFFQSxZQUFBLFlBQUEsZUFBQSxFQUFBLEVBQUE7OztBQUdBO0FBQ0E7OztBQUdBLGNBQUEsY0FBQTs7QUFFQSxvQkFBQSxlQUFBLEdBQUEsSUFBQSxDQUFBLFVBQUEsSUFBQSxFQUFBOzs7O0FBSUEsZ0JBQUEsSUFBQSxFQUFBO0FBQ0EsdUJBQUEsRUFBQSxDQUFBLFFBQUEsSUFBQSxFQUFBLFFBQUE7QUFDQSxhQUZBLE1BRUE7QUFDQSx1QkFBQSxFQUFBLENBQUEsT0FBQTtBQUNBO0FBQ0EsU0FUQTtBQVdBLEtBNUJBO0FBOEJBLENBdkNBOztBQ2ZBLElBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBOzs7QUFHQSxtQkFBQSxLQUFBLENBQUEsT0FBQSxFQUFBO0FBQ0EsYUFBQSxRQURBO0FBRUEsb0JBQUEsaUJBRkE7QUFHQSxxQkFBQTtBQUhBLEtBQUE7QUFNQSxDQVRBOztBQVdBLElBQUEsVUFBQSxDQUFBLGlCQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsYUFBQSxFQUFBOzs7QUFHQSxXQUFBLE1BQUEsR0FBQSxFQUFBLE9BQUEsQ0FBQSxhQUFBLENBQUE7QUFFQSxDQUxBO0FDWEEsSUFBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxtQkFBQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsYUFBQSxPQURBO0FBRUEscUJBQUE7QUFGQSxLQUFBO0FBSUEsQ0FMQTs7QUNBQSxJQUFBLFVBQUEsQ0FBQSxjQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBLGVBQUEsRUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxLQUFBO0FBQ0EsV0FBQSxXQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLEdBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxXQUFBLENBQUEsSUFBQSxDQUFBLEdBQUE7QUFDQSxLQUZBOztBQUlBLFdBQUEsUUFBQSxHQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0Esd0JBQUEsUUFBQSxDQUFBLElBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxJQUFBLEVBQUE7QUFDQSxtQkFBQSxTQUFBLEdBQUEsSUFBQTtBQUNBLFNBSEE7QUFJQSxLQUxBOztBQU9BLFdBQUEsV0FBQSxHQUFBLFVBQUEsS0FBQSxFQUFBLEVBQUEsRUFBQTtBQUNBLHdCQUFBLFdBQUEsQ0FBQSxLQUFBLEVBQUEsRUFBQTtBQUNBLGVBQUEsRUFBQSxDQUFBLE9BQUEsRUFBQSxFQUFBLFFBQUEsT0FBQSxTQUFBLENBQUEsTUFBQSxFQUFBLEVBQUEsRUFBQSxRQUFBLElBQUEsRUFBQTtBQUNBLEtBSEE7QUFJQSxDQXBCQTs7QUNBQSxJQUFBLE9BQUEsQ0FBQSxpQkFBQSxFQUFBLFVBQUEsS0FBQSxFQUFBOztBQUVBLFFBQUEsa0JBQUEsRUFBQTs7QUFFQSxhQUFBLFNBQUEsQ0FBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLElBQUEsSUFBQTtBQUNBOztBQUVB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LElBQUEsRUFBQTtBQUNBLHVCQUFBLEdBQUEsSUFBQSxDQUFBLFFBQUEsSUFBQSxDQUFBO0FBQ0E7Ozs7O0FBS0EsbUJBQUEsTUFBQSxHQUFBLENBQUEsVUFBQSxFQUFBLElBQUEsQ0FBQSxpQkFBQSxFQUFBLEtBQUEsQ0FBQSxZQUFBO0FBQ0EsdUJBQUEsSUFBQTtBQUNBLGFBRkEsQ0FBQTtBQUlBLFNBckJBOztBQXVCQSxhQUFBLE1BQUEsR0FBQSxVQUFBLFdBQUEsRUFBQTtBQUNBLG1CQUFBLE1BQUEsSUFBQSxDQUFBLFNBQUEsRUFBQSxXQUFBLEVBQ0EsSUFEQSxDQUNBLGlCQURBLEVBRUEsS0FGQSxDQUVBLFlBQUE7QUFDQSx1QkFBQSxHQUFBLE1BQUEsQ0FBQSxFQUFBLFNBQUEsNkJBQUEsRUFBQSxDQUFBO0FBQ0EsYUFKQSxDQUFBO0FBS0EsU0FOQTs7QUFRQSxhQUFBLEtBQUEsR0FBQSxVQUFBLFdBQUEsRUFBQTtBQUNBLG1CQUFBLE1BQUEsSUFBQSxDQUFBLFFBQUEsRUFBQSxXQUFBLEVBQ0EsSUFEQSxDQUNBLGlCQURBLEVBRUEsS0FGQSxDQUVBLFlBQUE7QUFDQSx1QkFBQSxHQUFBLE1BQUEsQ0FBQSxFQUFBLFNBQUEsNEJBQUEsRUFBQSxDQUFBO0FBQ0EsYUFKQSxDQUFBO0FBS0EsU0FOQTs7QUFRQSxhQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsbUJBQUEsTUFBQSxHQUFBLENBQUEsU0FBQSxFQUFBLElBQUEsQ0FBQSxZQUFBO0FBQ0Esd0JBQUEsT0FBQTtBQUNBLDJCQUFBLFVBQUEsQ0FBQSxZQUFBLGFBQUE7QUFDQSxhQUhBLENBQUE7QUFJQSxTQUxBO0FBT0EsS0E3REE7O0FBK0RBLFFBQUEsT0FBQSxDQUFBLFNBQUEsRUFBQSxVQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUE7O0FBRUEsWUFBQSxPQUFBLElBQUE7O0FBRUEsbUJBQUEsR0FBQSxDQUFBLFlBQUEsZ0JBQUEsRUFBQSxZQUFBO0FBQ0EsaUJBQUEsT0FBQTtBQUNBLFNBRkE7O0FBSUEsbUJBQUEsR0FBQSxDQUFBLFlBQUEsY0FBQSxFQUFBLFlBQUE7QUFDQSxpQkFBQSxPQUFBO0FBQ0EsU0FGQTs7QUFJQSxhQUFBLEVBQUEsR0FBQSxJQUFBO0FBQ0EsYUFBQSxJQUFBLEdBQUEsSUFBQTs7QUFFQSxhQUFBLE1BQUEsR0FBQSxVQUFBLFNBQUEsRUFBQSxJQUFBLEVBQUE7QUFDQSxpQkFBQSxFQUFBLEdBQUEsU0FBQTtBQUNBLGlCQUFBLElBQUEsR0FBQSxJQUFBO0FBQ0EsU0FIQTs7QUFLQSxhQUFBLE9BQUEsR0FBQSxZQUFBO0FBQ0EsaUJBQUEsRUFBQSxHQUFBLElBQUE7QUFDQSxpQkFBQSxJQUFBLEdBQUEsSUFBQTtBQUNBLFNBSEE7QUFLQSxLQXpCQTtBQTJCQSxDQTVJQTs7QUNBQSxJQUFBLFVBQUEsQ0FBQSxVQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBLE1BQUEsRUFBQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxNQUFBO0FBQ0EsQ0FIQTs7QUNBQSxJQUFBLE9BQUEsQ0FBQSxhQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUE7O0FBRUEsUUFBQSxjQUFBLEVBQUE7O0FBRUEsYUFBQSxTQUFBLENBQUEsR0FBQSxFQUFBO0FBQ0EsZUFBQSxJQUFBLElBQUE7QUFDQTs7QUFFQSxnQkFBQSxTQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsZUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGdCQUFBLFFBQUEsR0FBQSxVQUFBLElBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsSUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLFdBQUEsV0FBQTtBQUNBLENBbkJBO0FDQUEsSUFBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxtQkFBQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsYUFBQSxPQURBO0FBRUEscUJBQUEsbUJBRkE7QUFHQSxvQkFBQSxVQUhBO0FBSUEsaUJBQUE7QUFDQSxvQkFBQSxnQkFBQSxXQUFBLEVBQUE7QUFDQSx1QkFBQSxZQUFBLFNBQUEsRUFBQTtBQUNBLGFBSEE7QUFJQSwwQkFBQSxzQkFBQSxXQUFBLEVBQUE7QUFDQSx1QkFBQSxZQUFBLGVBQUEsRUFBQTtBQUNBO0FBTkE7QUFKQSxLQUFBO0FBYUEsQ0FkQTtBQ0FBLElBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0EsbUJBQUEsS0FBQSxDQUFBLGFBQUEsRUFBQTtBQUNBLGFBQUEsR0FEQTtBQUVBLHFCQUFBO0FBRkEsS0FBQTtBQU1BLENBUEE7QUNBQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTs7QUFFQSxtQkFBQSxLQUFBLENBQUEsT0FBQSxFQUFBO0FBQ0EsYUFBQSxRQURBO0FBRUEscUJBQUEscUJBRkE7QUFHQSxvQkFBQTtBQUhBLEtBQUE7QUFNQSxDQVJBOztBQVVBLElBQUEsVUFBQSxDQUFBLFdBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxXQUFBLEVBQUEsTUFBQSxFQUFBOztBQUVBLFdBQUEsS0FBQSxHQUFBLEVBQUE7QUFDQSxXQUFBLEtBQUEsR0FBQSxJQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLFVBQUEsU0FBQSxFQUFBOztBQUVBLGVBQUEsS0FBQSxHQUFBLElBQUE7O0FBRUEsb0JBQUEsS0FBQSxDQUFBLFNBQUEsRUFBQSxJQUFBLENBQUEsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxNQUFBO0FBQ0EsU0FGQSxFQUVBLEtBRkEsQ0FFQSxZQUFBO0FBQ0EsbUJBQUEsS0FBQSxHQUFBLDRCQUFBO0FBQ0EsU0FKQTtBQU1BLEtBVkE7QUFZQSxDQWpCQTs7QUNWQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTs7QUFFQSxtQkFBQSxLQUFBLENBQUEsYUFBQSxFQUFBO0FBQ0EsYUFBQSxlQURBO0FBRUEsa0JBQUEsbUVBRkE7QUFHQSxvQkFBQSxvQkFBQSxNQUFBLEVBQUEsV0FBQSxFQUFBO0FBQ0Esd0JBQUEsUUFBQSxHQUFBLElBQUEsQ0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLHVCQUFBLEtBQUEsR0FBQSxLQUFBO0FBQ0EsYUFGQTtBQUdBLFNBUEE7OztBQVVBLGNBQUE7QUFDQSwwQkFBQTtBQURBO0FBVkEsS0FBQTtBQWVBLENBakJBOztBQW1CQSxJQUFBLE9BQUEsQ0FBQSxhQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUE7O0FBRUEsUUFBQSxXQUFBLFNBQUEsUUFBQSxHQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSwyQkFBQSxFQUFBLElBQUEsQ0FBQSxVQUFBLFFBQUEsRUFBQTtBQUNBLG1CQUFBLFNBQUEsSUFBQTtBQUNBLFNBRkEsQ0FBQTtBQUdBLEtBSkE7O0FBTUEsV0FBQTtBQUNBLGtCQUFBO0FBREEsS0FBQTtBQUlBLENBWkE7QUNuQkE7O0FBRUEsSUFBQSxTQUFBLENBQUEsYUFBQSxFQUFBLFlBQUE7QUFDQSxXQUFBO0FBQ0EsZUFBQTtBQUNBLDBCQUFBO0FBREEsU0FEQTtBQUlBLGtCQUFBLEdBSkE7QUFLQSxxQkFBQTtBQUxBLEtBQUE7QUFPQSxDQVJBOztBQ0ZBLElBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBOztBQUVBLG1CQUFBLEtBQUEsQ0FBQSxRQUFBLEVBQUE7QUFDQSxhQUFBLFNBREE7QUFFQSxxQkFBQSx1QkFGQTtBQUdBLG9CQUFBO0FBSEEsS0FBQTtBQU1BLENBUkE7O0FBVUEsSUFBQSxVQUFBLENBQUEsWUFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsRUFBQTtBQUNBLFdBQUEsS0FBQSxHQUFBLElBQUE7O0FBRUEsV0FBQSxVQUFBLEdBQUEsVUFBQSxVQUFBLEVBQUE7QUFDQSxlQUFBLEtBQUEsR0FBQSxJQUFBO0FBQ0Esb0JBQUEsTUFBQSxDQUFBLFVBQUEsRUFBQSxJQUFBLENBQUEsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxNQUFBO0FBQ0EsU0FGQSxFQUVBLEtBRkEsQ0FFQSxZQUFBO0FBQ0EsbUJBQUEsS0FBQSxHQUFBLDhDQUFBO0FBQ0EsU0FKQTtBQU1BLEtBUkE7QUFVQSxDQWZBOztBQ1ZBLElBQUEsVUFBQSxDQUFBLHlCQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsaUJBQUEsRUFBQSxXQUFBLEVBQUEsWUFBQSxFQUFBLFdBQUEsRUFBQSxZQUFBLEVBQUEsTUFBQSxFQUFBLFFBQUEsRUFBQSxZQUFBLEVBQUEsU0FBQSxFQUFBLE9BQUEsRUFBQSxHQUFBLEVBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBOztBQUVBLFdBQUEsV0FBQSxHQUFBLFFBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsWUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxTQUFBOztBQUVBLFdBQUEsT0FBQSxHQUFBLE9BQUE7O0FBRUEsV0FBQSxHQUFBLEdBQUEsR0FBQTs7QUFFQSxXQUFBLFdBQUEsR0FBQSxZQUFBOztBQUVBLGVBQUEsT0FBQSxHQUFBLEtBQUEsR0FBQTtBQUNBLGdCQUFBLEdBQUEsQ0FBQSxPQUFBLE9BQUE7QUFDQSxLQUpBOztBQVFBLGFBQUEsYUFBQSxHQUFBO0FBQ0EsZUFBQSxPQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsUUFBQSxTQUFBLENBQUEsQ0FBQTs7QUFHQSxhQUFBLElBQUEsSUFBQSxJQUFBLEtBQUEsRUFBQTtBQUNBLGdCQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxJQUFBO0FBQ0E7QUFDQTtBQUNBOztBQUVBOzs7QUFJQSxhQUFBLFVBQUEsR0FBQTtBQUNBLGVBQUEsYUFBQSxHQUFBLEVBQUE7QUFDQSxpQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxZQUFBLEVBQUE7QUFDQSxpQkFBQSxJQUFBLElBQUEsSUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxTQUFBLFlBQUEsSUFBQSxTQUFBLFlBQUEsRUFBQSxVQUFBLElBQUEsQ0FBQSxJQUFBLElBQUEsQ0FBQTtBQUNBO0FBQ0EsbUJBQUEsYUFBQSxDQUFBLElBQUEsQ0FBQSxTQUFBO0FBQ0EsU0FOQTtBQU9BOzs7QUFHQTs7QUFHQSxXQUFBLGFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxPQUFBLEVBQUEsT0FBQSxFQUFBLEdBQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSwwQkFBQSxLQUFBO0FBQ0EscUJBQUEsYUFBQSxDQUFBLE1BQUEsRUFBQSxPQUFBLEVBQUEsT0FBQSxFQUFBLEdBQUEsRUFBQSxHQUFBLEVBQ0EsSUFEQSxDQUNBLFlBQUE7QUFDQSxtQkFBQSxFQUFBLENBQUEsY0FBQSxFQUFBLEVBQUEsUUFBQSxPQUFBLE1BQUEsRUFBQSxXQUFBLE9BQUEsU0FBQSxFQUFBLEVBQUEsRUFBQSxRQUFBLElBQUEsRUFBQTtBQUNBLFNBSEE7QUFJQSxLQU5BOztBQVVBLFdBQUEsRUFBQSxHQUFBLFlBQUE7QUFDQSwwQkFBQSxLQUFBLENBQUEsT0FBQSxRQUFBLENBQUEsSUFBQTtBQUNBLEtBRkE7O0FBSUEsV0FBQSxNQUFBLEdBQUEsWUFBQTtBQUNBLDBCQUFBLE9BQUEsQ0FBQSxRQUFBO0FBQ0EsS0FGQTtBQUdBLENBdEVBO0FDQUEsSUFBQSxVQUFBLENBQUEsY0FBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxJQUFBLEVBQUE7O0FBRUEsV0FBQSxLQUFBLEdBQUEsQ0FBQSxPQUFBLEVBQUEsT0FBQSxFQUFBLE9BQUEsQ0FBQTs7QUFFQSxXQUFBLGlCQUFBLEdBQUEsSUFBQTs7QUFFQSxXQUFBLElBQUEsR0FBQSxVQUFBLElBQUEsRUFBQTs7QUFFQSxZQUFBLGdCQUFBLFVBQUEsSUFBQSxDQUFBO0FBQ0EsdUJBQUEsT0FBQSxpQkFEQTtBQUVBLHlCQUFBLHNCQUZBO0FBR0Esd0JBQUEsc0JBSEE7QUFJQSxrQkFBQSxJQUpBO0FBS0EscUJBQUE7QUFDQSx1QkFBQSxpQkFBQTtBQUNBLDJCQUFBLE9BQUEsS0FBQTtBQUNBO0FBSEE7QUFMQSxTQUFBLENBQUE7O0FBWUEsc0JBQUEsTUFBQSxDQUFBLElBQUEsQ0FBQSxVQUFBLFlBQUEsRUFBQTtBQUNBLG1CQUFBLFFBQUEsR0FBQSxZ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Q0EsZ0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxPQUFBLENBQUEsSUFBQSxDQUFBLElBQUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7OztBQUlBLGFBQUEsVUFBQSxHQUFBO0FBQ0EsWUFBQSxLQUFBO0FBQ0EsZUFBQSxhQUFBLEdBQUEsRUFBQTtBQUNBLGtCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLFlBQUEsRUFBQTtBQUNBLGlCQUFBLElBQUEsSUFBQSxJQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBLFVBQUEsSUFBQSxDQUFBLElBQUEsSUFBQSxDQUFBO0FBQ0E7QUFDQSxtQkFBQSxhQUFBLENBQUEsSUFBQSxDQUFBLFNBQUE7QUFDQSxTQU5BO0FBT0E7OztBQUdBO0FBR0EsQ0FyQ0E7QUNBQSxJQUFBLFVBQUEsQ0FBQSxnQkFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUE7O0FBRUEsV0FBQSxPQUFBLEdBQUEsVUFBQSxlQUFBLEVBQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxDQUFBLGVBQUEsRUFBQSxPQUFBLElBQUEsQ0FBQSxLQUNBO0FBQ0EsaUJBQUEsSUFBQSxJQUFBLElBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsVUFBQSxJQUFBLElBQUEsRUFBQSxRQUFBLEdBQUEsV0FBQSxFQUFBO0FBQ0Esb0JBQUEsWUFBQSxnQkFBQSxRQUFBLEdBQUEsV0FBQSxFQUFBO0FBQ0Esd0JBQUEsR0FBQSxDQUFBLE9BQUEsRUFBQSxTQUFBLEVBQUEsUUFBQSxPQUFBLENBQUEsU0FBQSxNQUFBLENBQUEsQ0FBQTtBQUNBLG9CQUFBLFFBQUEsT0FBQSxDQUFBLFNBQUEsTUFBQSxDQUFBLENBQUEsRUFBQSxPQUFBLElBQUE7QUFDQTtBQUNBO0FBQ0EsZUFBQSxLQUFBO0FBQ0EsS0FYQTtBQWFBLENBZkE7QUNBQSxJQUFBLFVBQUEsQ0FBQSxpQkFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUEsV0FBQSxFQUFBLE9BQUEsRUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLFlBQUEsRUFBQSxJQUFBLEVBQUE7Ozs7QUFJQSxXQUFBLFNBQUEsR0FBQSxhQUFBLE1BQUE7QUFDQSxXQUFBLFlBQUEsR0FBQSxhQUFBLFNBQUE7QUFDQSxXQUFBLFdBQUEsR0FBQSxZQUFBLENBQUEsRUFBQSxJQUFBLENBQUEsVUFBQSxDQUFBLEVBQUEsQ0FBQSxFQUFBO0FBQ0EsWUFBQSxFQUFBLEVBQUEsR0FBQSxFQUFBLEVBQUEsRUFBQSxPQUFBLENBQUE7QUFDQSxZQUFBLEVBQUEsRUFBQSxHQUFBLEVBQUEsRUFBQSxFQUFBLE9BQUEsQ0FBQSxDQUFBO0FBQ0EsZUFBQSxDQUFBO0FBQ0EsS0FKQSxDQUFBO0FBS0EsV0FBQSxXQUFBLEdBQUEsS0FBQTtBQUNBLFdBQUEsWUFBQSxHQUFBLFlBQUE7O0FBR0EsYUFBQSxnQkFBQSxHQUFBO0FBQ0EsWUFBQSxjQUFBLEVBQUE7QUFDQSxlQUFBLFlBQUEsQ0FBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxJQUFBLE1BQUEsS0FBQSxPQUFBLFlBQUEsSUFBQSxJQUFBLGFBQUEsS0FBQSxRQUFBLEVBQUE7QUFDQSw0QkFBQSxJQUFBLE1BQUEsSUFBQSxJQUFBLE1BQUE7QUFDQSxhQUZBLE1BRUEsSUFBQSxJQUFBLE1BQUEsS0FBQSxPQUFBLFlBQUEsSUFBQSxJQUFBLGFBQUEsS0FBQSxRQUFBLEVBQUE7QUFDQSw0QkFBQSxJQUFBLE1BQUEsSUFBQSxJQUFBLE1BQUE7QUFDQTtBQUNBLFNBTkE7QUFPQSxlQUFBLFdBQUEsR0FBQSxXQUFBO0FBQ0E7O0FBRUE7O0FBR0EsV0FBQSxZQUFBLEdBQUEsWUFBQTs7QUFFQSxXQUFBLE9BQUEsR0FBQSxDQUFBOztBQUVBLFdBQUEsR0FBQSxHQUFBLE9BQUEsV0FBQSxDQUFBLEdBQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGVBQUEsSUFBQSxFQUFBO0FBQ0EsS0FGQSxDQUFBOzs7QUFLQSxXQUFBLFVBQUEsR0FBQSxLQUFBO0FBQ0EsV0FBQSxZQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsVUFBQSxHQUFBLENBQUEsT0FBQSxVQUFBO0FBQ0EsS0FGQTs7QUFJQSxXQUFBLGNBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsYUFBQSxFQUFBO0FBQ0EsYUFBQSxJQUFBLElBQUEsY0FBQSxNQUFBLEdBQUEsQ0FBQSxFQUFBLEtBQUEsQ0FBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLE1BQUEsY0FBQSxDQUFBLENBQUE7QUFDQSxnQkFBQSxTQUFBLENBQUE7QUFDQSxvQkFBQSxHQUFBLENBQUEsR0FBQTtBQUNBLGdCQUFBLElBQUEsUUFBQSxFQUFBO0FBQ0EsNkJBQUEsU0FBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsSUFBQSxRQUFBLEVBQUEsQ0FBQSxFQUFBLE9BQUEsQ0FBQSxFQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSwyQkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsaUJBSkE7QUFLQTtBQUNBO0FBQ0EsZUFBQSxVQUFBLEdBQUEsS0FBQTtBQUNBLEtBZEE7O0FBZ0JBLFdBQUEsU0FBQSxHQUFBLFVBQUEsYUFBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLFdBQUEsRUFBQTtBQUNBLDBCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFFBQUEsR0FBQSxJQUFBO0FBQ0EsYUFGQTtBQUdBLFNBSkEsTUFJQTtBQUNBLDBCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFFBQUEsR0FBQSxLQUFBO0FBQ0EsYUFGQTtBQUdBO0FBQ0EsS0FWQTs7QUFZQSxXQUFBLGdCQUFBLEdBQUEsVUFBQSxhQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsV0FBQSxLQUFBLElBQUEsRUFBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxLQUFBO0FBQ0E7QUFDQSxLQUpBOztBQU1BLFdBQUEsU0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxHQUFBLEVBQUEsYUFBQSxFQUFBO0FBQ0EsWUFBQSxTQUFBLGNBQUEsTUFBQSxHQUFBLENBQUE7QUFDQSxxQkFBQSxTQUFBLENBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxHQUFBLEVBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE1BQUEsRUFBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxNQUFBO0FBQ0E7QUFDQSxTQUpBO0FBS0EsS0FQQTs7QUFTQSxXQUFBLFlBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUFBO0FBQ0EscUJBQUEsWUFBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE1BQUEsRUFBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxNQUFBO0FBQ0E7QUFDQTtBQUNBLFNBTEE7QUFNQSxLQVBBOztBQVNBLFdBQUEsTUFBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLFNBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxDQUFBLFVBQUEsT0FBQSxFQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBLFFBQUEsTUFBQSxDQUFBLENBQUEsRUFBQSxLQUFBO0FBQ0EsU0FGQTtBQUdBLFlBQUEsU0FBQSxPQUFBLElBQUEsQ0FBQSxVQUFBLENBQUEsRUFBQSxDQUFBLEVBQUE7QUFDQSxtQkFBQSxJQUFBLENBQUE7QUFDQSxTQUZBLENBQUE7QUFHQSxZQUFBLE9BQUEsTUFBQSxHQUFBLENBQUEsRUFBQTtBQUNBLHlCQUFBLE1BQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsYUFKQTtBQU1BLFNBUEEsTUFPQTtBQUNBLHlCQUFBLE1BQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLENBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsYUFKQTtBQUtBO0FBQ0EsS0F0QkE7O0FBd0JBLFdBQUEsU0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQTtBQUNBLFlBQUEsVUFBQSxPQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsR0FBQSxFQUFBLEtBQUEsQ0FBQSxNQUFBLENBQUE7QUFDQSxZQUFBLE9BQUEsRUFBQTtBQUNBLGdCQUFBLGFBQUEsUUFBQSxJQUFBLENBQUEsVUFBQSxDQUFBLEVBQUEsQ0FBQSxFQUFBO0FBQ0EsdUJBQUEsSUFBQSxDQUFBO0FBQ0EsYUFGQSxDQUFBO0FBR0EsZ0JBQUEsV0FBQSxPQUFBLFdBQUEsQ0FBQSxDQUFBLElBQUEsQ0FBQTtBQUNBLGdCQUFBLGFBQUEsWUFBQSxTQUFBLFFBQUEsRUFBQTs7QUFFQSx5QkFBQSxTQUFBLENBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxVQUFBLEVBQ0EsSUFEQSxDQUNBLFlBQUE7QUFDQSx1QkFBQSxhQUFBLGNBQUEsQ0FBQSxhQUFBLE1BQUEsRUFBQSxhQUFBLFNBQUEsQ0FBQTtBQUNBLGFBSEEsRUFJQSxJQUpBLENBSUEsVUFBQSxRQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLEdBQUEsU0FBQSxDQUFBLENBQUE7QUFDQTtBQUNBO0FBQ0EsYUFSQTtBQVNBLFNBaEJBLE1BZ0JBO0FBQ0EsZ0JBQUEsYUFBQSxPQUFBLE9BQUEsQ0FBQSxNQUFBLEdBQUEsQ0FBQTtBQUNBLGdCQUFBLGFBQUEsWUFBQSxVQUFBO0FBQ0EseUJBQUEsU0FBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUNBLElBREEsQ0FDQSxZQUFBO0FBQ0EsdUJBQUEsYUFBQSxjQUFBLENBQUEsYUFBQSxNQUFBLEVBQUEsYUFBQSxTQUFBLENBQUE7QUFDQSxhQUhBLEVBSUEsSUFKQSxDQUlBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsdUJBQUEsV0FBQSxHQUFBLFNBQUEsQ0FB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QUZBOztBQUlBLFdBQUEsV0FBQSxHQUFBLGFBQUEsV0FBQTs7Ozs7Ozs7QUFTQSxXQUFBLGVBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsYUFBQSxHQUFBLFVBQUEsR0FBQSxFQUFBLFVBQUEsRUFBQSxDQUFBLEVBQUE7QUFDQSxlQUFBLE9BQUEsQ0FBQSxDQUFBLElBQUEsVUFBQTs7QUFFQSxZQUFBLFNBQUEsRUFBQSxRQUFBLE9BQUEsZUFBQSxDQUFBLENBQUEsQ0FBQSxFQUFBLFFBQUEsVUFBQSxFQUFBOzs7QUFHQSxZQUFBLE9BQUEsZUFBQSxDQUFBLE1BQUEsS0FBQSxDQUFBLEVBQUE7QUFBQSxtQkFBQSxlQUFBLENBQUEsSUFBQSxDQUFBLE1BQUE7QUFBQSxTQUFBLE1BQUE7QUFDQSxpQkFBQSxJQUFBLElBQUEsQ0FBQSxFQUFBLElBQUEsT0FBQSxlQUFBLENBQUEsTUFBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLE9BQUEsZUFBQSxDQUFBLENBQUEsRUFBQSxNQUFBLEtBQUEsT0FBQSxNQUFBLEVBQUE7QUFDQSwyQkFBQSxlQUFBLENBQUEsQ0FBQSxJQUFBLE1BQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQSxtQkFBQSxlQUFBLENBQUEsSUFBQSxDQUFBLE1BQUE7QUFDQTs7QUFFQSxLQWhCQTs7OztBQW9CQSxXQUFBLGVBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLFVBQUEsR0FBQSxFQUFBLE9BQUEsRUFBQSxHQUFBLEVBQUEsQ0FBQSxFQUFBLENBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxPQUFBLGVBQUE7QUFDQSxZQUFBLFFBQUEsS0FBQTtBQUNBLFlBQUEsVUFBQSxLQUFBLENBQUEsQ0FBQTtBQUNBLGFBQUEsSUFBQSxJQUFBLENBQUEsRUFBQSxJQUFBLE9BQUEsZUFBQSxDQUFBLE1BQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxNQUFBLE9BQUEsZUFBQSxDQUFBLENBQUEsQ0FBQTtBQUNBLG9CQUFBLEdBQUEsQ0FBQSxHQUFBO0FBQ0EsZ0JBQUEsSUFBQSxJQUFBLE1BQUEsQ0FBQSxFQUFBO0FBQ0Esd0JBQUEsSUFBQTtBQUNBLG9CQUFBLElBQUEsT0FBQSxDQUFBLEVBQUEsSUFBQSxPQUFBLElBQUEsT0FBQTtBQUNBLG9CQUFBLE9BQUEsSUFBQSxPQUFBO0FBQ0E7QUFDQTtBQUNBLFlBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSxnQkFBQSxTQUFBLEVBQUE7QUFDQSxtQkFBQSxJQUFBLElBQUEsQ0FBQTtBQUNBLG1CQUFBLE9BQUEsSUFBQSxPQUFBO0FBQ0EsbUJBQUEsZUFBQSxDQUFBLElBQUEsQ0FBQSxNQUFBO0FBQ0E7QUFDQSxLQW5CQTs7QUFxQkEsV0FBQSxhQUFBLEdBQUEsWUFBQTtBQUNBLFlBQUEsT0FBQSxFQUFBLE1BQUEsT0FBQSxlQUFBLEVBQUEsU0FBQSxPQUFBLGVBQUEsRUFBQTtBQUNBLHFCQUFBLGFBQUEsQ0FBQSxPQUFBLFNBQUEsRUFBQSxPQUFBLFlBQUEsRUFBQSxJQUFBO0FBQ0EsS0FIQTs7QUFNQSxXQUFBLFdBQUEsR0FBQSxZQUFBO0FBQ0EscUJBQUEsV0FBQSxDQUFBLE9BQUEsWUFBQSxFQUNBLElBREEsQ0FDQSxZQUFBO0FBQ0EsbUJBQUEsRUFBQSxDQUFBLE9BQUEsRUFBQSxFQUFBLFFBQUEsT0FBQSxTQUFBLEVBQUEsRUFBQSxFQUFBLFFBQUEsSUFBQSxFQUFBO0FBQ0EsU0FIQTtBQUlBLEtBTEE7Ozs7QUFTQSxXQUFBLHdCQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLGFBQUEsR0FBQSxFQUFBOztBQUVBLGlCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsSUFBQSxNQUFBLEtBQUEsT0FBQSxZQUFBLElBQUEsT0FBQSx3QkFBQSxDQUFBLE9BQUEsQ0FBQSxJQUFBLE1BQUEsS0FBQSxDQUFBLENBQUEsRUFBQTtBQUNBLG1CQUFBLHdCQUFBLENBQUEsSUFBQSxDQUFBLElBQUEsTUFBQTtBQUNBLFNBRkEsTUFFQSxJQUFBLElBQUEsTUFBQSxLQUFBLE9BQUEsWUFBQSxJQUFBLE9BQUEsd0JBQUEsQ0FBQSxPQUFBLENBQUEsSUFBQSxNQUFBLEtBQUEsQ0FBQSxDQUFBLEVBQUE7QUFDQSxtQkFBQSx3QkFBQSxDQUFBLElBQUEsQ0FBQSxJQUFBLE1BQUE7QUFDQTtBQUNBLEtBTkE7O0FBUUEsV0FBQSxhQUFBLEdBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsYUFBQSxDQUFBLE9BQUEsQ0FBQSxPQUFBLHdCQUFBLENBQUEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBLEVBQUE7QUFDQSxtQkFBQSxhQUFBLENBQUEsSUFBQSxDQUFBLE9BQUEsd0JBQUEsQ0FBQSxHQUFBLENBQUE7QUFDQSxTQUZBLE1BRUE7QUFDQSxnQkFBQSxJQUFBLE9BQUEsYUFBQSxDQUFBLE9BQUEsQ0FBQSxPQUFBLHdCQUFBLENBQUEsR0FBQSxDQUFBLENBQUE7QUFDQSxtQkFBQSxhQUFBLENBQUEsTUFBQSxDQUFBLENBQUEsRUFBQSxDQUFBO0FBQ0E7QUFDQSxLQVBBOztBQVNBLFdBQUEsZUFBQSxHQUFBLEVBQUE7O0FBRUEsV0FBQSxrQkFBQSxHQUFBLFlBQUE7QUFDQSxZQUFBLHFCQUFBLEVBQUE7QUFDQSxlQUFBLGFBQUEsQ0FBQSxPQUFBLENBQUEsVUFBQSxTQUFBLEVBQUE7QUFDQSxtQkFBQSxtQkFBQSxJQUFBLENBQUEsYUFBQSxrQkFBQSxDQUFBLE9BQUEsU0FBQSxFQUFBLFNBQUEsQ0FBQSxDQUFBO0FBQ0EsU0FGQTtBQUdBLGdCQUFBLEdBQUEsQ0FBQSxrQkFBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE9BQUEsRUFBQTtBQUNBLG9CQUFBLE9BQUEsQ0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLHVCQUFBLGVBQUEsQ0FBQSxJQUFBLENBQUEsTUFBQTtBQUNBLHVCQUFBLFVBQUE7QUFDQSxhQUhBO0FBSUEsU0FOQTtBQVFBLEtBYkE7O0FBZUEsUUFBQSxrQkFBQSxFQUFBO0FBQ0EsUUFBQSxVQUFBOztBQUVBLFdBQUEsa0JBQUEsR0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsQ0FBQSxlQUFBLEVBQUEsa0JBQUEsRUFBQTs7QUFFQSxZQUFBLGFBQUEsT0FBQSxlQUFBLENBQUEsQ0FBQSxFQUFBLFNBQUEsRUFBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLFlBQUEsWUFBQSxJQUFBLFNBQUE7QUFDQSxxQkFBQSxTQUFBOztBQUVBLFlBQUEsQ0FBQSxnQkFBQSxTQUFBLENBQUEsRUFBQSxnQkFBQSxTQUFBLElBQUEsRUFBQTtBQUNBLFlBQUEsZ0JBQUEsU0FBQSxFQUFBLE9BQUEsQ0FBQSxVQUFBLE1BQUEsQ0FBQSxDQUFBLEVBQUE7QUFDQSw0QkFBQSxTQUFBLEVBQUEsTUFBQSxDQUFBLGdCQUFBLFNBQUEsRUFBQSxPQUFBLENBQUEsVUFBQSxDQUFBLEVBQUEsQ0FBQTtBQUNBLFNBRkEsTUFFQTtBQUNBLDRCQUFBLFNBQUEsRUFBQSxJQUFBLENBQUEsVUFBQTtBQUNBO0FBQ0EsZUFBQSxlQUFBLEdBQUEsZUFBQTtBQUNBLEtBZEE7OztBQWtCQSxXQUFBLGFBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsV0FBQTs7QUFFQSxXQUFBLEdBQUEsR0FBQSxFQUFBOzs7O0FBS0EsV0FBQSxPQUFBLEdBQUEsWUFBQTs7QUFFQSxZQUFBLGtCQUFBLE9BQUEsT0FBQSxDQUFBLEdBQUEsQ0FBQSxVQUFBLE9BQUEsRUFBQTtBQUNBLG1CQUFBLE9BQUEsWUFBQSxHQUFBLEdBQUEsR0FBQSxPQUFBO0FBQ0EsU0FGQSxDQUFBO0FBR0EsYUFBQSxJQUFBLElBQUEsSUFBQSxPQUFBLGVBQUEsRUFBQTtBQUNBLG1CQUFBLGVBQUEsQ0FBQSxJQUFBLEVBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0NBQUEsSUFBQSxDQUFBLE9BQUEsR0FBQSxHQUFBLEdBQUE7QUFDQSxhQUZBO0FBR0E7QUFDQSxxQkFBQSxPQUFBLENBQUEsT0FBQSxTQUFBLEVBQUEsT0FBQSxZQUFBLEVBQUEsT0FBQSxhQUFBLEVBQUEsT0FBQSxlQUFBLEVBQUEsT0FBQSxZQUFBLEVBQUEsZUFBQSxFQUNBLElBREEsQ0FDQSxVQUFBLFdBQUEsRUFBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxXQUFBO0FBQ0EsU0FIQSxFQUlBLElBSkEsQ0FJQSxZQUFBO0FBQ0EsbUJBQUEsRUFBQSxDQUFBLG9CQUFBO0FBQ0EsU0FOQTtBQU9BLEtBakJBOztBQW1CQSxXQUFBLGlCQUFBLEdBQUEsSUFBQTs7QUFFQSxXQUFBLElBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxPQUFBLEVBQUEsR0FBQSxFQUFBLEtBQUEsRUFBQTs7QUFFQSxZQUFBLGdCQUFBLFVBQUEsSUFBQSxDQUFBO0FBQ0EsdUJBQUEsT0FBQSxpQkFEQTtBQUVBLHNCQUFBLEtBRkE7QUFHQSx5QkFBQSxpQ0FIQTtBQUlBLHdCQUFBLHlCQUpBO0FBS0EscUJBQUE7QUFDQSw2QkFBQSx1QkFBQTtBQUNBLDJCQUFBLE9BQUEsV0FBQTtBQUNBLGlCQUhBO0FBSUEsMEJBQUEsa0JBQUEsWUFBQSxFQUFBO0FBQ0EsNEJBQUEsR0FBQSxDQUFBLE9BQUE7QUFDQSwyQkFBQSxhQUFBLFdBQUEsQ0FBQSxNQUFBLEVBQUEsT0FBQSxDQUFBO0FBQ0EsaUJBUEE7QUFRQSw4QkFBQSx3QkFBQTtBQUNBLDJCQUFBLE9BQUE7QUFDQSxpQkFWQTtBQVdBLDJCQUFBLHFCQUFBO0FBQ0EsMkJBQUEsT0FBQSxZQUFBO0FBQ0EsaUJBYkE7QUFjQSx5QkFBQSxtQkFBQTtBQUNBLDJCQUFBLEdBQUE7QUFDQSxpQkFoQkE7QUFpQkEscUJBQUEsZUFBQTtBQUNBLDJCQUFBLEtBQUE7QUFDQTtBQW5CQTtBQUxBLFNBQUEsQ0FBQTs7QUE0QkEsc0JBQUEsTUFBQSxDQUFBLElBQUEsQ0FBQSxZQUFBO0FBQ0Esb0JBQUEsR0FBQSxDQUFBLFFBQUE7QUFDQSxtQkFBQSxVQUFBO0FBQ0EsU0FIQTtBQUlBLEtBbENBOztBQW9DQSxXQUFBLGVBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxpQkFBQSxHQUFBLENBQUEsT0FBQSxpQkFBQTtBQUNBLEtBRkE7O0FBSUEsV0FBQSxZQUFBLEdBQUEsRUFBQTtBQUNBLFdBQUEsV0FBQSxHQUFBLENBQUE7QUFDQSxXQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsV0FBQSxPQUFBLEdBQUEsQ0FBQTs7QUFFQSxXQUFBLE1BQUEsQ0FBQSwwQkFBQSxFQUFBLFlBQUE7QUFDQSxZQUFBLFFBQUEsQ0FBQSxPQUFBLFdBQUEsR0FBQSxDQUFBLElBQUEsT0FBQSxVQUFBO0FBQ0EsWUFBQSxNQUFBLFFBQUEsT0FBQSxVQUFBO0FBQ0EsZUFBQSxZQUFBLEdBQUEsT0FBQSxhQUFBLENBQUEsS0FBQSxDQUFBLEtBQUEsRUFBQSxHQUFBLENBQUE7QUFDQSxLQUpBOztBQU1BLFdBQUEsTUFBQSxDQUFBLGVBQUEsRUFBQSxZQUFBO0FBQ0EsWUFBQSxRQUFBLENBQUEsT0FBQSxXQUFBLEdBQUEsQ0FBQSxJQUFBLE9BQUEsVUFBQTtBQUNBLFlBQUEsTUFBQSxRQUFBLE9BQUEsVUFBQTtBQUNBLGVBQUEsWUFBQSxHQUFBLE9BQUEsYUFBQSxDQUFBLEtBQUEsQ0FBQSxLQUFBLEVBQUEsR0FBQSxDQUFBO0FBQ0EsS0FKQTtBQU1BLENBeGNBOztBQ0FBLElBQUEsVUFBQSxDQUFBLFdBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsTUFBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUEsU0FBQSxFQUFBLFdBQUEsRUFBQSxZQUFBLEVBQUEsVUFBQSxFQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLFNBQUE7O0FBRUEsV0FBQSxXQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxhQUFBLE1BQUE7O0FBRUEsV0FBQSxZQUFBLEdBQUEsWUFBQTs7QUFFQSxXQUFBLFVBQUEsR0FBQSxVQUFBOztBQUVBLFdBQUEsZ0JBQUEsR0FBQSxhQUFBLE1BQUEsR0FBQSxRQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLE9BQUEsU0FBQSxDQUFBLElBQUEsQ0FBQSxNQUFBOztBQUVBLFdBQUEsR0FBQSxHQUFBLFlBQUE7QUFDQSxlQUFBLFdBQUEsQ0FBQSxJQUFBLENBQUEsR0FBQTtBQUNBLEtBRkE7O0FBSUEsV0FBQSxNQUFBLEdBQUEsTUFBQSxDOztBQUVBLFdBQUEsZ0JBQUEsR0FBQSxDQUFBLFFBQUEsRUFBQSxTQUFBLENBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLEtBQUE7O0FBRUEsV0FBQSxnQkFBQSxHQUFBLFVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsU0FBQSxHQUFBLElBQUE7QUFDQSxxQkFBQSxnQkFBQSxDQUFBLFdBQUEsRUFBQSxNQUFBOzs7O0FBSUEsS0FOQTs7QUFRQSxXQUFBLFlBQUEsR0FBQSxVQUFBLFNBQUEsRUFBQTtBQUNBLFlBQUEsY0FBQSxlQUFBLElBQUEsY0FBQSxtQkFBQSxFQUFBLE9BQUEsSUFBQTtBQUNBLEtBRkE7O0FBSUEsV0FBQSxXQUFBLEdBQUEsVUFBQSxLQUFBLEVBQUE7QUFDQSxxQkFBQSxXQUFBLENBQUEsS0FBQSxFQUNBLElBREEsQ0FDQSxZQUFBO0FBQ0EsbUJBQUEsRUFBQSxDQUFBLE9BQUEsRUFBQSxFQUFBLFFBQUEsT0FBQSxNQUFBLEVBQUEsRUFBQSxFQUFBLFFBQUEsSUFBQSxFQUFBO0FBQ0EsU0FIQTtBQUlBLEtBTEE7O0FBT0EsV0FBQSxjQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsVUFBQSxDQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLElBQUEsVUFBQSxLQUFBLE9BQUEsS0FBQSxDQUFBLE1BQUEsSUFBQSxJQUFBLFdBQUEsS0FBQSxPQUFBLEtBQUEsQ0FBQSxNQUFBLEVBQUEsT0FBQSxJQUFBLEdBQUEsSUFBQSxTQUFBO0FBQ0EsU0FGQTtBQUdBLEtBSkE7O0FBTUEsV0FBQSxhQUFBLEdBQUEsRUFBQTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBMkJBLFdBQUEsV0FBQSxHQUFBLGFBQUEsV0FBQTtBQUVBLENBbEZBOztBQ0FBLElBQUEsT0FBQSxDQUFBLGNBQUEsRUFBQSxVQUFBLEtBQUEsRUFBQSxZQUFBLEVBQUE7O0FBRUEsUUFBQSxlQUFBLEVBQUE7O0FBRUEsYUFBQSxTQUFBLENBQUEsR0FBQSxFQUFBO0FBQ0EsZUFBQSxJQUFBLElBQUE7QUFDQTs7QUFFQSxpQkFBQSxZQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1CQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxjQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxTQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1CQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxNQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLElBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEdBQUEsU0FBQSxFQUFBLElBQUEsQ0FBQTtBQUNBLEtBRkE7O0FBSUEsaUJBQUEsYUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxJQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLGtCQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxFQUFBLElBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxNQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxJQUFBLENBQUEseUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQUEsRUFBQSxXQUFBLFNBQUEsRUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFNBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsS0FBQSxFQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEdBQUEsR0FBQSxHQUFBLEtBQUEsR0FBQSxHQUFBLEdBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFlBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsVUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLE1BQUEsQ0FBQSxtQkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsR0FBQSxVQUFBLEdBQUEsVUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFNBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLElBQUEsQ0FBQSw0QkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxDQUFBO0FBQ0EsS0FGQTtBQUdBLGlCQUFBLFdBQUEsR0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLGNBQUEsTUFBQSxHQUFBLGFBQUEsTUFBQTtBQUNBLGVBQUEsTUFBQSxJQUFBLENBQUEsZUFBQSxFQUFBLEtBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FKQTs7QUFNQSxpQkFBQSxXQUFBLEdBQUEsVUFBQSxZQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsTUFBQSxDQUFBLG1CQUFBLGFBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxhQUFBLFNBQUEsQ0FBQTtBQUNBLEtBRkE7O0FBSUEsaUJBQUEsZ0JBQUEsR0FBQSxVQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxjQUFBLEVBQUEsV0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGVBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG9DQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGtCQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1DQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxhQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLGlDQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxrQkFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUNBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsT0FBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLE1BQUEsRUFBQSxhQUFBLEVBQUEsZUFBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsRUFBQTtBQUNBLGFBQUEsTUFBQSxHQUFBLE1BQUE7QUFDQSxhQUFBLE1BQUEsR0FBQSxjQUFBLENBQUEsQ0FBQTtBQUNBLGFBQUEsYUFBQSxHQUFBLGFBQUE7QUFDQSxhQUFBLGVBQUEsR0FBQSxlQUFBO0FBQ0EsYUFBQSxZQUFBLEdBQUEsWUFBQTs7OztBQUlBLHFCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLElBQUEsTUFBQSxLQUFBLE1BQUEsSUFBQSxJQUFBLE1BQUEsS0FBQSxLQUFBLE1BQUEsRUFBQTtBQUNBLHFCQUFBLEtBQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSxvQkFBQSxJQUFBLGFBQUEsS0FBQSxRQUFBLEVBQUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EseUJBQUEsTUFBQSxHQUFBLElBQUEsTUFBQTtBQUNBLGlCQUhBLE1BSUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EseUJBQUEsTUFBQSxHQUFBLElBQUEsTUFBQTtBQUNBO0FBQ0EsYUFWQSxNQVdBLElBQUEsSUFBQSxNQUFBLEtBQUEsS0FBQSxNQUFBLElBQUEsSUFBQSxNQUFBLEtBQUEsTUFBQSxFQUFBO0FBQ0EscUJBQUEsS0FBQSxHQUFBLElBQUEsTUFBQTtBQUNBLG9CQUFBLElBQUEsYUFBQSxLQUFBLFNBQUEsRUFBQTtBQUNBLHlCQUFBLE1BQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EsaUJBSEEsTUFJQTtBQUNBLHlCQUFBLE1BQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0E7QUFDQTtBQUNBLFNBdkJBOztBQXlCQSxlQUFBLE1BQUEsR0FBQSxDQUFBLHVCQUFBLEVBQUEsSUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQXJDQTs7QUF1Q0EsaUJBQUEsY0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsR0FBQSxHQUFBLEdBQUEsRUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsV0FBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLE9BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsMkJBQUEsTUFB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JztcbndpbmRvdy5hcHAgPSBhbmd1bGFyLm1vZHVsZSgnRnVsbHN0YWNrR2VuZXJhdGVkQXBwJywgWydmc2FQcmVCdWlsdCcsICd1aS5yb3V0ZXInLCAndWkuYm9vdHN0cmFwJywgJ25nQW5pbWF0ZSddKTtcblxuYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHVybFJvdXRlclByb3ZpZGVyLCAkbG9jYXRpb25Qcm92aWRlcikge1xuICAgIC8vIFRoaXMgdHVybnMgb2ZmIGhhc2hiYW5nIHVybHMgKC8jYWJvdXQpIGFuZCBjaGFuZ2VzIGl0IHRvIHNvbWV0aGluZyBub3JtYWwgKC9hYm91dClcbiAgICAkbG9jYXRpb25Qcm92aWRlci5odG1sNU1vZGUodHJ1ZSk7XG4gICAgLy8gSWYgd2UgZ28gdG8gYSBVUkwgdGhhdCB1aS1yb3V0ZXIgZG9lc24ndCBoYXZlIHJlZ2lzdGVyZWQsIGdvIHRvIHRoZSBcIi9cIiB1cmwuXG4gICAgJHVybFJvdXRlclByb3ZpZGVyLm90aGVyd2lzZSgnLycpO1xuICAgIC8vIFRyaWdnZXIgcGFnZSByZWZyZXNoIHdoZW4gYWNjZXNzaW5nIGFuIE9BdXRoIHJvdXRlXG4gICAgJHVybFJvdXRlclByb3ZpZGVyLndoZW4oJy9hdXRoLzpwcm92aWRlcicsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgd2luZG93LmxvY2F0aW9uLnJlbG9hZCgpO1xuICAgIH0pO1xufSk7XG5cbi8vIFRoaXMgYXBwLnJ1biBpcyBmb3IgY29udHJvbGxpbmcgYWNjZXNzIHRvIHNwZWNpZmljIHN0YXRlcy5cbmFwcC5ydW4oZnVuY3Rpb24gKCRyb290U2NvcGUsIEF1dGhTZXJ2aWNlLCAkc3RhdGUpIHtcblxuICAgIC8vIFRoZSBnaXZlbiBzdGF0ZSByZXF1aXJlcyBhbiBhdXRoZW50aWNhdGVkIHVzZXIuXG4gICAgdmFyIGRlc3RpbmF0aW9uU3RhdGVSZXF1aXJlc0F1dGggPSBmdW5jdGlvbiAoc3RhdGUpIHtcbiAgICAgICAgcmV0dXJuIHN0YXRlLmRhdGEgJiYgc3RhdGUuZGF0YS5hdXRoZW50aWNhdGU7XG4gICAgfTtcblxuICAgIC8vICRzdGF0ZUNoYW5nZVN0YXJ0IGlzIGFuIGV2ZW50IGZpcmVkXG4gICAgLy8gd2hlbmV2ZXIgdGhlIHByb2Nlc3Mgb2YgY2hhbmdpbmcgYSBzdGF0ZSBiZWdpbnMuXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24gKGV2ZW50LCB0b1N0YXRlLCB0b1BhcmFtcykge1xuXG4gICAgICAgIGlmICghZGVzdGluYXRpb25TdGF0ZVJlcXVpcmVzQXV0aCh0b1N0YXRlKSkge1xuICAgICAgICAgICAgLy8gVGhlIGRlc3RpbmF0aW9uIHN0YXRlIGRvZXMgbm90IHJlcXVpcmUgYXV0aGVudGljYXRpb25cbiAgICAgICAgICAgIC8vIFNob3J0IGNpcmN1aXQgd2l0aCByZXR1cm4uXG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoQXV0aFNlcnZpY2UuaXNBdXRoZW50aWNhdGVkKCkpIHtcbiAgICAgICAgICAgIC8vIFRoZSB1c2VyIGlzIGF1dGhlbnRpY2F0ZWQuXG4gICAgICAgICAgICAvLyBTaG9ydCBjaXJjdWl0IHdpdGggcmV0dXJuLlxuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gQ2FuY2VsIG5hdmlnYXRpbmcgdG8gbmV3IHN0YXRlLlxuICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuXG4gICAgICAgIEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpLnRoZW4oZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgICAgIC8vIElmIGEgdXNlciBpcyByZXRyaWV2ZWQsIHRoZW4gcmVuYXZpZ2F0ZSB0byB0aGUgZGVzdGluYXRpb25cbiAgICAgICAgICAgIC8vICh0aGUgc2Vjb25kIHRpbWUsIEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpIHdpbGwgd29yaylcbiAgICAgICAgICAgIC8vIG90aGVyd2lzZSwgaWYgbm8gdXNlciBpcyBsb2dnZWQgaW4sIGdvIHRvIFwibG9naW5cIiBzdGF0ZS5cbiAgICAgICAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgICAgICAgICAgJHN0YXRlLmdvKHRvU3RhdGUubmFtZSwgdG9QYXJhbXMpO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAkc3RhdGUuZ28oJ2xvZ2luJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuXG4gICAgfSk7XG5cbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcblxuICAgIC8vIFJlZ2lzdGVyIG91ciAqYWJvdXQqIHN0YXRlLlxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhYm91dCcsIHtcbiAgICAgICAgdXJsOiAnL2Fib3V0JyxcbiAgICAgICAgY29udHJvbGxlcjogJ0Fib3V0Q29udHJvbGxlcicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvYWJvdXQvYWJvdXQuaHRtbCdcbiAgICB9KTtcblxufSk7XG5cbmFwcC5jb250cm9sbGVyKCdBYm91dENvbnRyb2xsZXInLCBmdW5jdGlvbiAoJHNjb3BlLCBGdWxsc3RhY2tQaWNzKSB7XG5cbiAgICAvLyBJbWFnZXMgb2YgYmVhdXRpZnVsIEZ1bGxzdGFjayBwZW9wbGUuXG4gICAgJHNjb3BlLmltYWdlcyA9IF8uc2h1ZmZsZShGdWxsc3RhY2tQaWNzKTtcblxufSk7IiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnZG9jcycsIHtcbiAgICAgICAgdXJsOiAnL2RvY3MnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2RvY3MvZG9jcy5odG1sJ1xuICAgIH0pO1xufSk7XG4iLCJhcHAuY29udHJvbGxlcignQ3JlYXRlZGJDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHN0YXRlLCBDcmVhdGVkYkZhY3RvcnkpIHtcblxuXHQkc2NvcGUuY3JlYXRlZERCID0gZmFsc2U7XG4gICAgICAgICRzY29wZS5jb2x1bW5BcnJheSA9IFtdO1xuXG5cdCRzY29wZS5hZGQgPSBmdW5jdGlvbigpIHtcblx0XHQkc2NvcGUuY29sdW1uQXJyYXkucHVzaCgnMScpO1xuXHR9XG5cblx0JHNjb3BlLmNyZWF0ZURCID0gZnVuY3Rpb24obmFtZSkge1xuXHRcdENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVEQihuYW1lKVxuXHRcdC50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcblx0XHRcdCRzY29wZS5jcmVhdGVkREIgPSBkYXRhO1xuXHRcdH0pXG5cdH1cblxuXHQkc2NvcGUuY3JlYXRlVGFibGUgPSBmdW5jdGlvbih0YWJsZSwgREIpe1xuXHRcdENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVUYWJsZSh0YWJsZSwgREIpXG5cdFx0XHQkc3RhdGUuZ28oJ1RhYmxlJywge2RiTmFtZTogJHNjb3BlLmNyZWF0ZWREQi5kYk5hbWV9LCB7cmVsb2FkOnRydWV9KVxuXHR9XG59KTtcbiIsImFwcC5mYWN0b3J5KCdDcmVhdGVkYkZhY3RvcnknLCBmdW5jdGlvbiAoJGh0dHApIHtcblxuXHR2YXIgQ3JlYXRlZGJGYWN0b3J5ID0ge307XG5cblx0ZnVuY3Rpb24gcmVzVG9EYXRhKHJlcykge1xuICAgICAgICByZXR1cm4gcmVzLmRhdGE7XG4gICAgfVxuXG4gICAgQ3JlYXRlZGJGYWN0b3J5LmNyZWF0ZURCID0gZnVuY3Rpb24oZGJOYW1lKSB7XG4gICAgXHRyZXR1cm4gJGh0dHAucG9zdCgnL2FwaS9tYXN0ZXJkYicsIGRiTmFtZSlcbiAgICBcdC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgIENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVUYWJsZSA9IGZ1bmN0aW9uKHRhYmxlLCBjcmVhdGVkREIpIHtcbiAgICB0YWJsZS5kYk5hbWUgPSBjcmVhdGVkREIuZGJOYW1lO1xuICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL2NsaWVudGRiJywgdGFibGUpXG4gICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgIH1cblxuXHRyZXR1cm4gQ3JlYXRlZGJGYWN0b3J5OyBcbn0pXG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdjcmVhdGVkYicsIHtcbiAgICAgICAgdXJsOiAnL2NyZWF0ZWRiJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jcmVhdGVkYi9jcmVhdGVkYi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0NyZWF0ZWRiQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgXHRsb2dnZWRJblVzZXI6IGZ1bmN0aW9uKEF1dGhTZXJ2aWNlKSB7XG4gICAgICAgIFx0XHRyZXR1cm4gQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCk7XG4gICAgICAgIFx0fVxuICAgICAgICB9XG4gICAgfSk7XG5cbn0pOyIsIihmdW5jdGlvbiAoKSB7XG5cbiAgICAndXNlIHN0cmljdCc7XG5cbiAgICAvLyBIb3BlIHlvdSBkaWRuJ3QgZm9yZ2V0IEFuZ3VsYXIhIER1aC1kb3kuXG4gICAgaWYgKCF3aW5kb3cuYW5ndWxhcikgdGhyb3cgbmV3IEVycm9yKCdJIGNhblxcJ3QgZmluZCBBbmd1bGFyIScpO1xuXG4gICAgdmFyIGFwcCA9IGFuZ3VsYXIubW9kdWxlKCdmc2FQcmVCdWlsdCcsIFtdKTtcblxuICAgIGFwcC5mYWN0b3J5KCdTb2NrZXQnLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmICghd2luZG93LmlvKSB0aHJvdyBuZXcgRXJyb3IoJ3NvY2tldC5pbyBub3QgZm91bmQhJyk7XG4gICAgICAgIHJldHVybiB3aW5kb3cuaW8od2luZG93LmxvY2F0aW9uLm9yaWdpbik7XG4gICAgfSk7XG5cbiAgICAvLyBBVVRIX0VWRU5UUyBpcyB1c2VkIHRocm91Z2hvdXQgb3VyIGFwcCB0b1xuICAgIC8vIGJyb2FkY2FzdCBhbmQgbGlzdGVuIGZyb20gYW5kIHRvIHRoZSAkcm9vdFNjb3BlXG4gICAgLy8gZm9yIGltcG9ydGFudCBldmVudHMgYWJvdXQgYXV0aGVudGljYXRpb24gZmxvdy5cbiAgICBhcHAuY29uc3RhbnQoJ0FVVEhfRVZFTlRTJywge1xuICAgICAgICBsb2dpblN1Y2Nlc3M6ICdhdXRoLWxvZ2luLXN1Y2Nlc3MnLFxuICAgICAgICBsb2dpbkZhaWxlZDogJ2F1dGgtbG9naW4tZmFpbGVkJyxcbiAgICAgICAgbG9nb3V0U3VjY2VzczogJ2F1dGgtbG9nb3V0LXN1Y2Nlc3MnLFxuICAgICAgICBzZXNzaW9uVGltZW91dDogJ2F1dGgtc2Vzc2lvbi10aW1lb3V0JyxcbiAgICAgICAgbm90QXV0aGVudGljYXRlZDogJ2F1dGgtbm90LWF1dGhlbnRpY2F0ZWQnLFxuICAgICAgICBub3RBdXRob3JpemVkOiAnYXV0aC1ub3QtYXV0aG9yaXplZCdcbiAgICB9KTtcblxuICAgIGFwcC5mYWN0b3J5KCdBdXRoSW50ZXJjZXB0b3InLCBmdW5jdGlvbiAoJHJvb3RTY29wZSwgJHEsIEFVVEhfRVZFTlRTKSB7XG4gICAgICAgIHZhciBzdGF0dXNEaWN0ID0ge1xuICAgICAgICAgICAgNDAxOiBBVVRIX0VWRU5UUy5ub3RBdXRoZW50aWNhdGVkLFxuICAgICAgICAgICAgNDAzOiBBVVRIX0VWRU5UUy5ub3RBdXRob3JpemVkLFxuICAgICAgICAgICAgNDE5OiBBVVRIX0VWRU5UUy5zZXNzaW9uVGltZW91dCxcbiAgICAgICAgICAgIDQ0MDogQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXRcbiAgICAgICAgfTtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIHJlc3BvbnNlRXJyb3I6IGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChzdGF0dXNEaWN0W3Jlc3BvbnNlLnN0YXR1c10sIHJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHJlc3BvbnNlKVxuICAgICAgICAgICAgfVxuICAgICAgICB9O1xuICAgIH0pO1xuXG4gICAgYXBwLmNvbmZpZyhmdW5jdGlvbiAoJGh0dHBQcm92aWRlcikge1xuICAgICAgICAkaHR0cFByb3ZpZGVyLmludGVyY2VwdG9ycy5wdXNoKFtcbiAgICAgICAgICAgICckaW5qZWN0b3InLFxuICAgICAgICAgICAgZnVuY3Rpb24gKCRpbmplY3Rvcikge1xuICAgICAgICAgICAgICAgIHJldHVybiAkaW5qZWN0b3IuZ2V0KCdBdXRoSW50ZXJjZXB0b3InKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgXSk7XG4gICAgfSk7XG5cbiAgICBhcHAuc2VydmljZSgnQXV0aFNlcnZpY2UnLCBmdW5jdGlvbiAoJGh0dHAsIFNlc3Npb24sICRyb290U2NvcGUsIEFVVEhfRVZFTlRTLCAkcSkge1xuXG4gICAgICAgIGZ1bmN0aW9uIG9uU3VjY2Vzc2Z1bExvZ2luKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICB2YXIgZGF0YSA9IHJlc3BvbnNlLmRhdGE7XG4gICAgICAgICAgICBTZXNzaW9uLmNyZWF0ZShkYXRhLmlkLCBkYXRhLnVzZXIpO1xuICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KEFVVEhfRVZFTlRTLmxvZ2luU3VjY2Vzcyk7XG4gICAgICAgICAgICByZXR1cm4gZGF0YS51c2VyO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gVXNlcyB0aGUgc2Vzc2lvbiBmYWN0b3J5IHRvIHNlZSBpZiBhblxuICAgICAgICAvLyBhdXRoZW50aWNhdGVkIHVzZXIgaXMgY3VycmVudGx5IHJlZ2lzdGVyZWQuXG4gICAgICAgIHRoaXMuaXNBdXRoZW50aWNhdGVkID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuICEhU2Vzc2lvbi51c2VyO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMuZ2V0TG9nZ2VkSW5Vc2VyID0gZnVuY3Rpb24gKGZyb21TZXJ2ZXIpIHtcblxuICAgICAgICAgICAgLy8gSWYgYW4gYXV0aGVudGljYXRlZCBzZXNzaW9uIGV4aXN0cywgd2VcbiAgICAgICAgICAgIC8vIHJldHVybiB0aGUgdXNlciBhdHRhY2hlZCB0byB0aGF0IHNlc3Npb25cbiAgICAgICAgICAgIC8vIHdpdGggYSBwcm9taXNlLiBUaGlzIGVuc3VyZXMgdGhhdCB3ZSBjYW5cbiAgICAgICAgICAgIC8vIGFsd2F5cyBpbnRlcmZhY2Ugd2l0aCB0aGlzIG1ldGhvZCBhc3luY2hyb25vdXNseS5cblxuICAgICAgICAgICAgLy8gT3B0aW9uYWxseSwgaWYgdHJ1ZSBpcyBnaXZlbiBhcyB0aGUgZnJvbVNlcnZlciBwYXJhbWV0ZXIsXG4gICAgICAgICAgICAvLyB0aGVuIHRoaXMgY2FjaGVkIHZhbHVlIHdpbGwgbm90IGJlIHVzZWQuXG5cbiAgICAgICAgICAgIGlmICh0aGlzLmlzQXV0aGVudGljYXRlZCgpICYmIGZyb21TZXJ2ZXIgIT09IHRydWUpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gJHEud2hlbihTZXNzaW9uLnVzZXIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBNYWtlIHJlcXVlc3QgR0VUIC9zZXNzaW9uLlxuICAgICAgICAgICAgLy8gSWYgaXQgcmV0dXJucyBhIHVzZXIsIGNhbGwgb25TdWNjZXNzZnVsTG9naW4gd2l0aCB0aGUgcmVzcG9uc2UuXG4gICAgICAgICAgICAvLyBJZiBpdCByZXR1cm5zIGEgNDAxIHJlc3BvbnNlLCB3ZSBjYXRjaCBpdCBhbmQgaW5zdGVhZCByZXNvbHZlIHRvIG51bGwuXG4gICAgICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvc2Vzc2lvbicpLnRoZW4ob25TdWNjZXNzZnVsTG9naW4pLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5zaWdudXAgPSBmdW5jdGlvbihjcmVkZW50aWFscyl7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL3NpZ251cCcsIGNyZWRlbnRpYWxzKVxuICAgICAgICAgICAgLnRoZW4ob25TdWNjZXNzZnVsTG9naW4pXG4gICAgICAgICAgICAuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QoeyBtZXNzYWdlOiAnSW52YWxpZCBzaWdudXAgY3JlZGVudGlhbHMuJyB9KTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMubG9naW4gPSBmdW5jdGlvbiAoY3JlZGVudGlhbHMpIHtcbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvbG9naW4nLCBjcmVkZW50aWFscylcbiAgICAgICAgICAgICAgICAudGhlbihvblN1Y2Nlc3NmdWxMb2dpbilcbiAgICAgICAgICAgICAgICAuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHsgbWVzc2FnZTogJ0ludmFsaWQgbG9naW4gY3JlZGVudGlhbHMuJyB9KTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLmxvZ291dCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9sb2dvdXQnKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBTZXNzaW9uLmRlc3Ryb3koKTtcbiAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3QoQVVUSF9FVkVOVFMubG9nb3V0U3VjY2Vzcyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfTtcblxuICAgIH0pO1xuXG4gICAgYXBwLnNlcnZpY2UoJ1Nlc3Npb24nLCBmdW5jdGlvbiAoJHJvb3RTY29wZSwgQVVUSF9FVkVOVFMpIHtcblxuICAgICAgICB2YXIgc2VsZiA9IHRoaXM7XG5cbiAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMubm90QXV0aGVudGljYXRlZCwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgc2VsZi5kZXN0cm95KCk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBzZWxmLmRlc3Ryb3koKTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgdGhpcy5pZCA9IG51bGw7XG4gICAgICAgIHRoaXMudXNlciA9IG51bGw7XG5cbiAgICAgICAgdGhpcy5jcmVhdGUgPSBmdW5jdGlvbiAoc2Vzc2lvbklkLCB1c2VyKSB7XG4gICAgICAgICAgICB0aGlzLmlkID0gc2Vzc2lvbklkO1xuICAgICAgICAgICAgdGhpcy51c2VyID0gdXNlcjtcbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLmRlc3Ryb3kgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICB0aGlzLmlkID0gbnVsbDtcbiAgICAgICAgICAgIHRoaXMudXNlciA9IG51bGw7XG4gICAgICAgIH07XG5cbiAgICB9KTtcblxufSkoKTtcbiIsImFwcC5jb250cm9sbGVyKCdIb21lQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsIGFsbERicywgJHN0YXRlKSB7XG5cblx0JHNjb3BlLmFsbERicyA9IGFsbERicztcbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ0hvbWVGYWN0b3J5JywgZnVuY3Rpb24gKCRodHRwKSB7XG5cblx0dmFyIEhvbWVGYWN0b3J5ID0ge307XG5cblx0ZnVuY3Rpb24gcmVzVG9EYXRhKHJlcykge1xuICAgICAgICByZXR1cm4gcmVzLmRhdGE7XG4gICAgfVxuXG4gICAgSG9tZUZhY3RvcnkuZ2V0QWxsRGJzID0gZnVuY3Rpb24oKXtcbiAgICBcdHJldHVybiAkaHR0cC5nZXQoJy9hcGkvbWFzdGVyZGInKVxuICAgIFx0LnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIEhvbWVGYWN0b3J5LmRlbGV0ZURCID0gZnVuY3Rpb24obmFtZSl7XG4gICAgXHRyZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL21hc3RlcmRiLycgKyBuYW1lKVxuICAgIFx0LnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuXHRyZXR1cm4gSG9tZUZhY3Rvcnk7IFxufSkiLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdIb21lJywge1xuICAgICAgICB1cmw6ICcvaG9tZScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvSG9tZS9Ib21lLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnSG9tZUN0cmwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgIFx0YWxsRGJzOiBmdW5jdGlvbihIb21lRmFjdG9yeSl7XG4gICAgICAgIFx0XHRyZXR1cm4gSG9tZUZhY3RvcnkuZ2V0QWxsRGJzKCk7XG4gICAgICAgIFx0fSxcbiAgICAgICAgICAgIGxvZ2dlZEluVXNlcjogZnVuY3Rpb24gKEF1dGhTZXJ2aWNlKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSk7XG59KTsiLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdsYW5kaW5nUGFnZScsIHtcbiAgICAgICAgdXJsOiAnLycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvbGFuZGluZ1BhZ2UvbGFuZGluZ1BhZ2UuaHRtbCdcbiAgICAgICAgfVxuICAgICk7XG5cbn0pOyIsImFwcC5jb25maWcoZnVuY3Rpb24oJHN0YXRlUHJvdmlkZXIpIHtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdsb2dpbicsIHtcbiAgICAgICAgdXJsOiAnL2xvZ2luJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9sb2dpbi9sb2dpbi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0xvZ2luQ3RybCdcbiAgICB9KTtcblxufSk7XG5cbmFwcC5jb250cm9sbGVyKCdMb2dpbkN0cmwnLCBmdW5jdGlvbigkc2NvcGUsIEF1dGhTZXJ2aWNlLCAkc3RhdGUpIHtcblxuICAgICRzY29wZS5sb2dpbiA9IHt9O1xuICAgICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgICAkc2NvcGUuc2VuZExvZ2luID0gZnVuY3Rpb24obG9naW5JbmZvKSB7XG5cbiAgICAgICAgJHNjb3BlLmVycm9yID0gbnVsbDtcblxuICAgICAgICBBdXRoU2VydmljZS5sb2dpbihsb2dpbkluZm8pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oJ0hvbWUnKTtcbiAgICAgICAgfSkuY2F0Y2goZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAkc2NvcGUuZXJyb3IgPSAnSW52YWxpZCBsb2dpbiBjcmVkZW50aWFscy4nO1xuICAgICAgICB9KTtcblxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdtZW1iZXJzT25seScsIHtcbiAgICAgICAgdXJsOiAnL21lbWJlcnMtYXJlYScsXG4gICAgICAgIHRlbXBsYXRlOiAnPGltZyBuZy1yZXBlYXQ9XCJpdGVtIGluIHN0YXNoXCIgd2lkdGg9XCIzMDBcIiBuZy1zcmM9XCJ7eyBpdGVtIH19XCIgLz4nLFxuICAgICAgICBjb250cm9sbGVyOiBmdW5jdGlvbiAoJHNjb3BlLCBTZWNyZXRTdGFzaCkge1xuICAgICAgICAgICAgU2VjcmV0U3Rhc2guZ2V0U3Rhc2goKS50aGVuKGZ1bmN0aW9uIChzdGFzaCkge1xuICAgICAgICAgICAgICAgICRzY29wZS5zdGFzaCA9IHN0YXNoO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0sXG4gICAgICAgIC8vIFRoZSBmb2xsb3dpbmcgZGF0YS5hdXRoZW50aWNhdGUgaXMgcmVhZCBieSBhbiBldmVudCBsaXN0ZW5lclxuICAgICAgICAvLyB0aGF0IGNvbnRyb2xzIGFjY2VzcyB0byB0aGlzIHN0YXRlLiBSZWZlciB0byBhcHAuanMuXG4gICAgICAgIGRhdGE6IHtcbiAgICAgICAgICAgIGF1dGhlbnRpY2F0ZTogdHJ1ZVxuICAgICAgICB9XG4gICAgfSk7XG5cbn0pO1xuXG5hcHAuZmFjdG9yeSgnU2VjcmV0U3Rhc2gnLCBmdW5jdGlvbiAoJGh0dHApIHtcblxuICAgIHZhciBnZXRTdGFzaCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9tZW1iZXJzL3NlY3JldC1zdGFzaCcpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgfSk7XG4gICAgfTtcblxuICAgIHJldHVybiB7XG4gICAgICAgIGdldFN0YXNoOiBnZXRTdGFzaFxuICAgIH07XG5cbn0pOyIsIid1c2Ugc3RyaWN0JztcblxuYXBwLmRpcmVjdGl2ZSgnb2F1dGhCdXR0b24nLCBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiB7XG4gICAgc2NvcGU6IHtcbiAgICAgIHByb3ZpZGVyTmFtZTogJ0AnXG4gICAgfSxcbiAgICByZXN0cmljdDogJ0UnLFxuICAgIHRlbXBsYXRlVXJsOiAnL2pzL29hdXRoL29hdXRoLWJ1dHRvbi5odG1sJ1xuICB9XG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnc2lnbnVwJywge1xuICAgICAgICB1cmw6ICcvc2lnbnVwJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9zaWdudXAvc2lnbnVwLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnU2lnbnVwQ3RybCdcbiAgICB9KTtcblxufSk7XG5cbmFwcC5jb250cm9sbGVyKCdTaWdudXBDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICAgJHNjb3BlLnNpZ251cCA9IHt9O1xuICAgICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgICAkc2NvcGUuc2VuZFNpZ251cCA9IGZ1bmN0aW9uIChzaWdudXBJbmZvKSB7XG4gICAgICAgICRzY29wZS5lcnJvciA9IG51bGw7XG4gICAgICAgIEF1dGhTZXJ2aWNlLnNpZ251cChzaWdudXBJbmZvKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbygnaG9tZScpO1xuICAgICAgICB9KS5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAkc2NvcGUuZXJyb3IgPSAnT29wcywgY2Fubm90IHNpZ24gdXAgd2l0aCB0aG9zZSBjcmVkZW50aWFscy4nO1xuICAgICAgICB9KTtcblxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmNvbnRyb2xsZXIoJ0Fzc29jaWF0aW9uSW5zdGFuY2VDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHVpYk1vZGFsSW5zdGFuY2UsIGZvcmVpZ25Db2xzLCBUYWJsZUZhY3RvcnksIEhvbWVGYWN0b3J5LCAkc3RhdGVQYXJhbXMsICRzdGF0ZSwgZm9yVGFibGUsIGZvclRhYmxlTmFtZSwgY3VyclRhYmxlLCBjb2xOYW1lLCBpZDEpIHtcblxuICAkc2NvcGUuZGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZTtcblxuICAkc2NvcGUuc2luZ2xlVGFibGUgPSBmb3JUYWJsZTtcblxuICAkc2NvcGUuVGFibGVOYW1lID0gZm9yVGFibGVOYW1lO1xuXG4gICRzY29wZS5jdXJyVGFibGUgPSBjdXJyVGFibGU7XG5cbiAgJHNjb3BlLmNvbE5hbWUgPSBjb2xOYW1lO1xuXG4gICRzY29wZS5pZDEgPSBpZDE7XG5cbiAgJHNjb3BlLnNldFNlbGVjdGVkID0gZnVuY3Rpb24oKXtcblxuICAgICRzY29wZS5jdXJyUm93ID0gdGhpcy5yb3c7XG4gICAgY29uc29sZS5sb2coJHNjb3BlLmN1cnJSb3cpO1xuICB9XG5cbiBcblxuICBmdW5jdGlvbiBDcmVhdGVDb2x1bW5zKCl7XG4gICAgJHNjb3BlLmNvbHVtbnMgPSBbXTtcbiAgICB2YXIgdGFibGUgPSBmb3JUYWJsZVswXTtcblxuXG4gICAgZm9yKHZhciBwcm9wIGluIHRhYmxlKXtcbiAgICAgIGlmKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpe1xuICAgICAgICAkc2NvcGUuY29sdW1ucy5wdXNoKHByb3ApOyAgXG4gICAgICB9IFxuICAgIH1cbiAgfVxuXG4gICAgQ3JlYXRlQ29sdW1ucygpO1xuXG5cbiAgICAvL3RoaXMgZnVuY3Rpb24gd2lsbCByZSBydW4gd2hlbiB0aGUgZmlsdGVyIGZ1bmN0aW9uIGlzIGludm9rZWQsIGluIG9yZGVyIHRvIHJlcG9wdWxhdGUgdGhlIHRhYmxlXG4gICAgZnVuY3Rpb24gQ3JlYXRlUm93cygpIHtcbiAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkgPSBbXTtcbiAgICAgICAgZm9yVGFibGUuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIHZhciByb3dWYWx1ZXMgPSBbXTtcbiAgICAgICAgICAgIGZvciAodmFyIHByb3AgaW4gcm93KSB7XG4gICAgICAgICAgICAgICAgaWYgKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpIHJvd1ZhbHVlcy5wdXNoKHJvd1twcm9wXSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5LnB1c2gocm93VmFsdWVzKVxuICAgICAgICB9KVxuICAgIH1cblxuICAgIC8vIFNvcnQgdGhlIHZhbHVlcyBpbiBzaW5nbGVUYWJsZSBzbyB0aGF0IGFsbCB0aGUgdmFsdWVzIGZvciBhIGdpdmVuIHJvdyBhcmUgZ3JvdXBlZFxuICAgIENyZWF0ZVJvd3MoKTtcblxuXG4gICRzY29wZS5zZXRGb3JlaWduS2V5ID0gZnVuY3Rpb24oZGJOYW1lLCB0YmxOYW1lLCBjb2xOYW1lLCBpZDEsIGlkMil7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoKTtcbiAgICBUYWJsZUZhY3Rvcnkuc2V0Rm9yZWlnbktleShkYk5hbWUsIHRibE5hbWUsIGNvbE5hbWUsIGlkMSwgaWQyKVxuICAgIC50aGVuKGZ1bmN0aW9uKCl7XG4gICAgICAgICRzdGF0ZS5nbygnVGFibGUuU2luZ2xlJywgeyBkYk5hbWU6ICRzY29wZS5kYk5hbWUsIHRhYmxlTmFtZTogJHNjb3BlLmN1cnJUYWJsZSB9LCB7IHJlbG9hZDogdHJ1ZSB9KVxuICAgIH0pXG4gIH1cblxuXG5cbiAgJHNjb3BlLm9rID0gZnVuY3Rpb24gKCkge1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmNsb3NlKCRzY29wZS5zZWxlY3RlZC5pdGVtKTtcbiAgfTtcblxuICAkc2NvcGUuY2FuY2VsID0gZnVuY3Rpb24gKCkge1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmRpc21pc3MoJ2NhbmNlbCcpO1xuICB9O1xufSk7IiwiYXBwLmNvbnRyb2xsZXIoJ2RlbGV0ZURCQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsICR1aWJNb2RhbCwgJGxvZykge1xuXG4gICRzY29wZS5pdGVtcyA9IFsnaXRlbTEnLCAnaXRlbTInLCAnaXRlbTMnXTtcblxuICAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQgPSB0cnVlO1xuXG4gICRzY29wZS5vcGVuID0gZnVuY3Rpb24gKHNpemUpIHtcblxuICAgIHZhciBtb2RhbEluc3RhbmNlID0gJHVpYk1vZGFsLm9wZW4oe1xuICAgICAgYW5pbWF0aW9uOiAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQsXG4gICAgICB0ZW1wbGF0ZVVybDogJ2RlbGV0ZURCQ29udGVudC5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdkZWxldGVEQkluc3RhbmNlQ3RybCcsXG4gICAgICBzaXplOiBzaXplLFxuICAgICAgcmVzb2x2ZToge1xuICAgICAgICBpdGVtczogZnVuY3Rpb24gKCkge1xuICAgICAgICAgIHJldHVybiAkc2NvcGUuaXRlbXM7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcblxuICAgIG1vZGFsSW5zdGFuY2UucmVzdWx0LnRoZW4oZnVuY3Rpb24gKHNlbGVjdGVkSXRlbSkge1xuICAgICAgJHNjb3BlLnNlbGVjdGVkID0gc2VsZWN0ZWRJdGVtO1xuICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICRsb2cuaW5mbygnTW9kYWwgZGlzbWlzc2VkIGF0OiAnICsgbmV3IERhdGUoKSk7XG4gICAgfSk7XG4gIH07XG5cbiAgJHNjb3BlLnRvZ2dsZUFuaW1hdGlvbiA9IGZ1bmN0aW9uICgpIHtcbiAgICAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQgPSAhJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkO1xuICB9O1xuXG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ2RlbGV0ZURCSW5zdGFuY2VDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHVpYk1vZGFsSW5zdGFuY2UsIGl0ZW1zLCBUYWJsZUZhY3RvcnksIEhvbWVGYWN0b3J5LCAkc3RhdGVQYXJhbXMsICRzdGF0ZSkge1xuXG5cbiAgJHNjb3BlLmRyb3BEYlRleHQgPSAnRFJPUCBEQVRBQkFTRSdcbiAgJHNjb3BlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG5cbiAgJHNjb3BlLmRlbGV0ZVRoZURiID0gZnVuY3Rpb24oKXtcbiAgICAkdWliTW9kYWxJbnN0YW5jZS5jbG9zZSgkc2NvcGUuc2VsZWN0ZWQuaXRlbSk7XG4gICAgVGFibGVGYWN0b3J5LmRlbGV0ZURiKCRzY29wZS5kYk5hbWUpXG4gICAgLnRoZW4oZnVuY3Rpb24oKXtcbiAgICAgIEhvbWVGYWN0b3J5LmRlbGV0ZURCKCRzY29wZS5kYk5hbWUpXG4gICAgfSlcbiAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICRzdGF0ZS5nbygnSG9tZScsIHt9LCB7cmVsb2FkIDogdHJ1ZX0pXG4gICAgfSlcbiAgfVxuXG4gICRzY29wZS5pdGVtcyA9IGl0ZW1zO1xuICAkc2NvcGUuc2VsZWN0ZWQgPSB7XG4gICAgaXRlbTogJHNjb3BlLml0ZW1zWzBdXG4gIH07XG5cbiAgJHNjb3BlLm9rID0gZnVuY3Rpb24gKCkge1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmNsb3NlKCRzY29wZS5zZWxlY3RlZC5pdGVtKTtcbiAgfTtcblxuICAkc2NvcGUuY2FuY2VsID0gZnVuY3Rpb24gKCkge1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmRpc21pc3MoJ2NhbmNlbCcpO1xuICB9O1xufSk7IiwiYXBwLmNvbnRyb2xsZXIoJ0RlbGV0ZURiQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUpIHtcblxuICAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQgPSB0cnVlO1xuXG4gICRzY29wZS5vcGVuID0gZnVuY3Rpb24gKHNpemUpIHtcblxuICAgIHZhciBtb2RhbEluc3RhbmNlID0gJHVpYk1vZGFsLm9wZW4oe1xuICAgICAgYW5pbWF0aW9uOiAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQsXG4gICAgICB0ZW1wbGF0ZVVybDogJ2RlbGV0ZURiQ29udGVudC5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdEZWxldGVEYkluc3RhbmNlQ3RybCcsXG4gICAgICBzaXplOiBzaXplLFxuICAgICAgcmVzb2x2ZToge1xuICAgICAgICBpdGVtczogZnVuY3Rpb24gKCkge1xuICAgICAgICAgIHJldHVybiAkc2NvcGUuaXRlbXM7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcblxuICAgIG1vZGFsSW5zdGFuY2UucmVzdWx0LnRoZW4oZnVuY3Rpb24gKHNlbGVjdGVkSXRlbSkge1xuICAgICAgJHNjb3BlLnNlbGVjdGVkID0gc2VsZWN0ZWRJdGVtO1xuICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICRsb2cuaW5mbygnTW9kYWwgZGlzbWlzc2VkIGF0OiAnICsgbmV3IERhdGUoKSk7XG4gICAgfSk7XG4gIH07XG5cbn0pO1xuXG5cbmFwcC5jb250cm9sbGVyKCdEZWxldGVEYkluc3RhbmNlQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsICR1aWJNb2RhbEluc3RhbmNlLCBpdGVtcywgJHN0YXRlUGFyYW1zLCBUYWJsZUZhY3RvcnkpIHtcblxuICAkc2NvcGUuZGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZVxuXG4gICRzY29wZS5kcm9wRGF0YWJhc2UgPSAnRFJPUCBEQVRBQkFTRSdcblxuICAkc2NvcGUuZGVsZXRlID0gZnVuY3Rpb24gKCkge1xuICAgIFRhYmxlRmFjdG9yeS5kZWxldGVEYigkc2NvcGUuZGJOYW1lKVxuICAgIC8vICRzdGF0ZS5nbygnSG9tZScsIHt9LCB7cmVsb2FkIDogdHJ1ZX0pXG4gIH07XG5cbiAgJHNjb3BlLmNhbmNlbCA9IGZ1bmN0aW9uICgpIHtcbiAgICAkdWliTW9kYWxJbnN0YW5jZS5kaXNtaXNzKCdjYW5jZWwnKTtcbiAgfTtcbn0pOyIsImFwcC5jb250cm9sbGVyKCdKb2luVGFibGVDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMsIGpvaW5UYWJsZSkge1xuXG4gICAgJHNjb3BlLmpvaW5UYWJsZSA9IGpvaW5UYWJsZTtcblxuXG5cdGZ1bmN0aW9uIENyZWF0ZUNvbHVtbnMoKXtcblx0XHQkc2NvcGUuY29sdW1ucyA9IFtdO1xuXHRcdHZhciB0YWJsZSA9ICRzY29wZS5qb2luVGFibGVbMF07XG5cblxuXHRcdGZvcih2YXIgcHJvcCBpbiB0YWJsZSl7XG5cdFx0XHRpZihwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKXtcblx0XHRcdFx0JHNjb3BlLmNvbHVtbnMucHVzaChwcm9wKTtcdFxuXHRcdFx0fSBcblx0XHR9XG5cdH1cblxuICAgIENyZWF0ZUNvbHVtbnMoKTtcblxuXG4gICAgLy90aGlzIGZ1bmN0aW9uIHdpbGwgcmUgcnVuIHdoZW4gdGhlIGZpbHRlciBmdW5jdGlvbiBpcyBpbnZva2VkLCBpbiBvcmRlciB0byByZXBvcHVsYXRlIHRoZSB0YWJsZVxuICAgIGZ1bmN0aW9uIENyZWF0ZVJvd3MoKSB7XG4gICAgXHR2YXIgYWxpYXM7XG4gICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5ID0gW107XG4gICAgICAgIGpvaW5UYWJsZS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgdmFyIHJvd1ZhbHVlcyA9IFtdO1xuICAgICAgICAgICAgZm9yICh2YXIgcHJvcCBpbiByb3cpIHtcbiAgICAgICAgICAgICAgICBpZiAocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jykgcm93VmFsdWVzLnB1c2gocm93W3Byb3BdKVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkucHVzaChyb3dWYWx1ZXMpXG4gICAgICAgIH0pXG4gICAgfVxuXG4gICAgLy8gU29ydCB0aGUgdmFsdWVzIGluIHNpbmdsZVRhYmxlIHNvIHRoYXQgYWxsIHRoZSB2YWx1ZXMgZm9yIGEgZ2l2ZW4gcm93IGFyZSBncm91cGVkXG4gICAgQ3JlYXRlUm93cygpO1xuXG5cbn0pIiwiYXBwLmNvbnRyb2xsZXIoJ1F1ZXJ5VGFibGVDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcblxuICAgICRzY29wZS5xRmlsdGVyID0gZnVuY3Rpb24ocmVmZXJlbmNlU3RyaW5nLCB2YWwpe1xuICAgICAgICBpZighcmVmZXJlbmNlU3RyaW5nKSByZXR1cm4gdHJ1ZTtcbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBmb3IodmFyIHByb3AgaW4gdmFsKXtcbiAgICAgICAgICAgICAgICB2YXIgY2VsbFZhbCA9IHZhbFtwcm9wXS50b1N0cmluZygpLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgICAgICAgICAgdmFyIHNlYXJjaFZhbCA9IHJlZmVyZW5jZVN0cmluZy50b1N0cmluZygpLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgICAgICAgICAgY29uc29sZS5sb2coY2VsbFZhbCwgc2VhcmNoVmFsLCBjZWxsVmFsLmluZGV4T2Yoc2VhcmNoVmFsKSAhPT0gLTEpXG4gICAgICAgICAgICAgICAgaWYoY2VsbFZhbC5pbmRleE9mKHNlYXJjaFZhbCkgIT09IC0xKSByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG59KSIsImFwcC5jb250cm9sbGVyKCdTaW5nbGVUYWJsZUN0cmwnLCBmdW5jdGlvbigkc2NvcGUsIFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zLCBzaW5nbGVUYWJsZSwgJHdpbmRvdywgJHN0YXRlLCAkdWliTW9kYWwsIGFzc29jaWF0aW9ucywgJGxvZykge1xuXG4gICAgLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1B1dHRpbmcgc3R1ZmYgb24gc2NvcGUvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG5cbiAgICAkc2NvcGUudGhlRGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZTtcbiAgICAkc2NvcGUudGhlVGFibGVOYW1lID0gJHN0YXRlUGFyYW1zLnRhYmxlTmFtZTtcbiAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSBzaW5nbGVUYWJsZVswXS5zb3J0KGZ1bmN0aW9uKGEsIGIpe1xuICAgICAgICBpZihhLmlkID4gYi5pZCkgcmV0dXJuIDE7XG4gICAgICAgIGlmKGEuaWQgPCBiLmlkKSByZXR1cm4gLTE7XG4gICAgICAgIHJldHVybiAwO1xuICAgIH0pO1xuICAgICRzY29wZS5zZWxlY3RlZEFsbCA9IGZhbHNlO1xuICAgICRzY29wZS5hc3NvY2lhdGlvbnMgPSBhc3NvY2lhdGlvbnM7XG5cblxuICAgIGZ1bmN0aW9uIGZvcmVpZ25Db2x1bW5PYmooKSB7XG4gICAgICAgIHZhciBmb3JlaWduQ29scyA9IHt9O1xuICAgICAgICAkc2NvcGUuYXNzb2NpYXRpb25zLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICBpZiAocm93LlRhYmxlMSA9PT0gJHNjb3BlLnRoZVRhYmxlTmFtZSAmJiByb3cuUmVsYXRpb25zaGlwMSA9PT0gJ2hhc09uZScpIHtcbiAgICAgICAgICAgICAgICBmb3JlaWduQ29sc1tyb3cuQWxpYXMxXSA9IHJvdy5UYWJsZTJcbiAgICAgICAgICAgIH0gZWxzZSBpZiAocm93LlRhYmxlMiA9PT0gJHNjb3BlLnRoZVRhYmxlTmFtZSAmJiByb3cuUmVsYXRpb25zaGlwMiA9PT0gJ2hhc09uZScpIHtcbiAgICAgICAgICAgICAgICBmb3JlaWduQ29sc1tyb3cuQWxpYXMyXSA9IHJvdy5UYWJsZTFcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSlcbiAgICAgICAgJHNjb3BlLmZvcmVpZ25Db2xzID0gZm9yZWlnbkNvbHM7XG4gICAgfVxuXG4gICAgZm9yZWlnbkNvbHVtbk9iaigpO1xuXG5cbiAgICAkc2NvcGUuY3VycmVudFRhYmxlID0gJHN0YXRlUGFyYW1zO1xuXG4gICAgJHNjb3BlLm15SW5kZXggPSAxO1xuXG4gICAgJHNjb3BlLmlkcyA9ICRzY29wZS5zaW5nbGVUYWJsZS5tYXAoZnVuY3Rpb24ocm93KSB7XG4gICAgICAgIHJldHVybiByb3cuaWQ7XG4gICAgfSlcblxuICAgIC8vZGVsZXRlIGEgcm93IFxuICAgICRzY29wZS5zaG93RGVsZXRlID0gZmFsc2U7XG4gICAgJHNjb3BlLnRvZ2dsZURlbGV0ZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAkc2NvcGUuc2hvd0RlbGV0ZSA9ICEkc2NvcGUuc2hvd0RlbGV0ZVxuICAgIH1cblxuICAgICRzY29wZS5kZWxldGVTZWxlY3RlZCA9IGZ1bmN0aW9uKGRiLCB0YWJsZSwgaW5zdGFuY2VBcnJheSkge1xuICAgICAgICBmb3IodmFyIGkgPSBpbnN0YW5jZUFycmF5Lmxlbmd0aC0xOyBpID49IDA7IGktLSl7XG4gICAgICAgICAgICB2YXIgcm93ID0gaW5zdGFuY2VBcnJheVtpXTtcbiAgICAgICAgICAgIHZhciBsZW5ndGggPSBpO1xuICAgICAgICAgICAgY29uc29sZS5sb2cocm93KSAgICAgICBcbiAgICAgICAgICAgIGlmIChyb3cuc2VsZWN0ZWQpIHtcbiAgICAgICAgICAgICAgICBUYWJsZUZhY3RvcnkucmVtb3ZlUm93KGRiLCB0YWJsZSwgcm93Wyd2YWx1ZXMnXVswXVsndmFsdWUnXSwgbGVuZ3RoKVxuICAgICAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHJlc3VsdDtcbiAgICAgICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICAkc2NvcGUuc2hvd0RlbGV0ZSA9IGZhbHNlO1xuICAgIH1cblxuICAgICRzY29wZS5zZWxlY3RBbGwgPSBmdW5jdGlvbihpbnN0YW5jZUFycmF5KSB7XG4gICAgICAgIGlmICgkc2NvcGUuc2VsZWN0ZWRBbGwpIHtcbiAgICAgICAgICAgIGluc3RhbmNlQXJyYXkuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgICAgICByb3cuc2VsZWN0ZWQgPSB0cnVlO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGluc3RhbmNlQXJyYXkuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgICAgICByb3cuc2VsZWN0ZWQgPSBmYWxzZTtcbiAgICAgICAgICAgIH0pXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAkc2NvcGUudW5jaGVja1NlbGVjdEFsbCA9IGZ1bmN0aW9uKGluc3RhbmNlQXJyYXkpIHtcbiAgICAgICAgaWYgKCRzY29wZS5zZWxlY3RlZEFsbCA9PT0gdHJ1ZSkge1xuICAgICAgICAgICAgJHNjb3BlLnNlbGVjdGVkQWxsID0gZmFsc2U7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAkc2NvcGUucmVtb3ZlUm93ID0gZnVuY3Rpb24oZGIsIHRhYmxlLCByb3csIGluc3RhbmNlQXJyYXkpIHtcbiAgICAgICAgdmFyIGxlbmd0aCA9IGluc3RhbmNlQXJyYXkubGVuZ3RoIC0gMTtcbiAgICAgICAgVGFibGVGYWN0b3J5LnJlbW92ZVJvdyhkYiwgdGFibGUsIHJvdywgbGVuZ3RoKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0O1xuICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgIH0pXG4gICAgfVxuXG4gICAgJHNjb3BlLnJlbW92ZUNvbHVtbiA9IGZ1bmN0aW9uKGRiLCB0YWJsZSwgY29sdW1uTmFtZSkge1xuICAgICAgICBUYWJsZUZhY3RvcnkucmVtb3ZlQ29sdW1uKGRiLCB0YWJsZSwgY29sdW1uTmFtZSlcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHJlc3VsdDtcbiAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICAgICAgQ3JlYXRlQ29sdW1ucygpO1xuICAgICAgICAgICAgfSlcbiAgICB9XG5cbiAgICAkc2NvcGUubmV3Um93ID0gZnVuY3Rpb24oZGIsIHRhYmxlLCBhcnIpIHtcbiAgICAgICAgdmFyIGFsbElkcyA9IFtdO1xuICAgICAgICBhcnIuZm9yRWFjaChmdW5jdGlvbihyb3dEYXRhKSB7XG4gICAgICAgICAgICBhbGxJZHMucHVzaChyb3dEYXRhLnZhbHVlc1swXS52YWx1ZSlcbiAgICAgICAgfSlcbiAgICAgICAgdmFyIHNvcnRlZCA9IGFsbElkcy5zb3J0KGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgICAgICAgIHJldHVybiBiIC0gYVxuICAgICAgICB9KVxuICAgICAgICBpZiAoc29ydGVkLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgIFRhYmxlRmFjdG9yeS5hZGRSb3coZGIsIHRhYmxlLCBzb3J0ZWRbMF0gKyAxKVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICB9KVxuXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBUYWJsZUZhY3RvcnkuYWRkUm93KGRiLCB0YWJsZSwgMSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0O1xuICAgICAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS5hZGRDb2x1bW4gPSBmdW5jdGlvbihkYiwgdGFibGUpIHtcbiAgICAgICAgdmFyIGNvbE51bXMgPSAkc2NvcGUuY29sdW1ucy5qb2luKCcgJykubWF0Y2goL1xcZCsvZyk7XG4gICAgICAgIGlmIChjb2xOdW1zKSB7XG4gICAgICAgICAgICB2YXIgc29ydGVkTnVtcyA9IGNvbE51bXMuc29ydChmdW5jdGlvbihhLCBiKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGIgLSBhXG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgdmFyIG51bUluTmV3ID0gTnVtYmVyKHNvcnRlZE51bXNbMF0pICsgMTtcbiAgICAgICAgICAgIHZhciBuYW1lTmV3Q29sID0gJ0NvbHVtbiAnICsgbnVtSW5OZXcudG9TdHJpbmcoKTtcblxuICAgICAgICAgICAgVGFibGVGYWN0b3J5LmFkZENvbHVtbihkYiwgdGFibGUsIG5hbWVOZXdDb2wpXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0U2luZ2xlVGFibGUoJHN0YXRlUGFyYW1zLmRiTmFtZSwgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSlcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHRoZVRhYmxlKSB7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHRoZVRhYmxlWzBdO1xuICAgICAgICAgICAgICAgICAgICBDcmVhdGVDb2x1bW5zKCk7XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdmFyIG5leHRDb2xOdW0gPSAkc2NvcGUuY29sdW1ucy5sZW5ndGggKyAxO1xuICAgICAgICAgICAgdmFyIG5ld0NvbE5hbWUgPSAnQ29sdW1uICcgKyBuZXh0Q29sTnVtO1xuICAgICAgICAgICAgVGFibGVGYWN0b3J5LmFkZENvbHVtbihkYiwgdGFibGUsICdDb2x1bW4gMScpXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0U2luZ2xlVGFibGUoJHN0YXRlUGFyYW1zLmRiTmFtZSwgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSlcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHRoZVRhYmxlKSB7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHRoZVRhYmxlWzBdO1xuICAgICAgICAgICAgICAgICAgICBDcmVhdGVDb2x1bW5zKCk7XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICB9XG5cbiAgICB9XG5cbiAgICAvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vT3JnYW5pemluZyBzdHVmZiBpbnRvIGFycmF5cy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgIC8vIEdldCBhbGwgb2YgdGhlIGNvbHVtbnMgdG8gY3JlYXRlIHRoZSBjb2x1bW5zIG9uIHRoZSBib290c3RyYXAgdGFibGVcblxuICAgIGZ1bmN0aW9uIENyZWF0ZUNvbHVtbnMoKSB7XG4gICAgICAgICRzY29wZS5jb2x1bW5zID0gW107XG4gICAgICAgICRzY29wZS5vcmlnaW5hbENvbFZhbHMgPSBbXTtcbiAgICAgICAgdmFyIHRhYmxlID0gJHNjb3BlLnNpbmdsZVRhYmxlWzBdO1xuXG5cbiAgICAgICAgZm9yICh2YXIgcHJvcCBpbiB0YWJsZSkge1xuICAgICAgICAgICAgaWYgKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuY29sdW1ucy5wdXNoKHByb3ApO1xuICAgICAgICAgICAgICAgICRzY29wZS5vcmlnaW5hbENvbFZhbHMucHVzaChwcm9wKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cblxuICAgIENyZWF0ZUNvbHVtbnMoKTtcblxuICAgIGZ1bmN0aW9uIGNyZWF0ZVZpcnR1YWxDb2x1bW5zKCkge1xuICAgICAgICBpZiAoJHNjb3BlLmFzc29jaWF0aW9ucy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAkc2NvcGUudmlydHVhbENvbHVtbnMgPSBbXTtcbiAgICAgICAgICAgICRzY29wZS5hc3NvY2lhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgICAgICBpZiAocm93LlRhYmxlMSA9PT0gJHNjb3BlLnRoZVRhYmxlTmFtZSAmJiByb3cuUmVsYXRpb25zaGlwMSA9PT0gJ2hhc01hbnknKSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciB2aXJ0dWFsID0ge307XG4gICAgICAgICAgICAgICAgICAgIHZpcnR1YWwubmFtZSA9IHJvdy5BbGlhczE7XG4gICAgICAgICAgICAgICAgICAgIGlmIChyb3cuVGhyb3VnaCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC50YWJsZSA9IHJvdy5UaHJvdWdoO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5jb2x1bW5rZXkgPSByb3cuQWxpYXMxO1xuICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC50YWJsZSA9IHJvdy5UYWJsZTI7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLmNvbHVtbmtleSA9IHJvdy5BbGlhczI7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnZpcnR1YWxDb2x1bW5zLnB1c2godmlydHVhbCk7XG4gICAgICAgICAgICAgICAgfSBlbHNlIGlmIChyb3cuVGFibGUyID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmIHJvdy5SZWxhdGlvbnNoaXAyID09PSAnaGFzTWFueScpIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHZpcnR1YWwgPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5uYW1lID0gcm93LkFsaWFzMjtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHJvdy5UaHJvdWdoKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLnRhYmxlID0gcm93LlRocm91Z2g7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLmNvbHVtbmtleSA9IHJvdy5BbGlhczI7XG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLnRhYmxlID0gcm93LlRhYmxlMTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwuY29sdW1ua2V5ID0gcm93LkFsaWFzMTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAkc2NvcGUudmlydHVhbENvbHVtbnMucHVzaCh2aXJ0dWFsKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgY3JlYXRlVmlydHVhbENvbHVtbnMoKTtcblxuICAgIC8vdGhpcyBmdW5jdGlvbiB3aWxsIHJlIHJ1biB3aGVuIHRoZSBmaWx0ZXIgZnVuY3Rpb24gaXMgaW52b2tlZCwgaW4gb3JkZXIgdG8gcmVwb3B1bGF0ZSB0aGUgdGFibGVcbiAgICBmdW5jdGlvbiBDcmVhdGVSb3dzKCkge1xuICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheSA9IFtdO1xuICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIHZhciByb3dWYWx1ZXMgPSBbXTtcbiAgICAgICAgICAgIHZhciByb3dPYmogPSB7fTtcblxuICAgICAgICAgICAgZm9yICh2YXIgcHJvcCBpbiByb3cpIHtcbiAgICAgICAgICAgICAgICBpZiAocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jykgcm93VmFsdWVzLnB1c2goe1xuICAgICAgICAgICAgICAgICAgICBjb2w6IHByb3AsXG4gICAgICAgICAgICAgICAgICAgIHZhbHVlOiByb3dbcHJvcF1cbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcm93T2JqLnZhbHVlcyA9IHJvd1ZhbHVlcztcbiAgICAgICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5LnB1c2gocm93T2JqKTtcbiAgICAgICAgfSlcbiAgICB9XG5cbiAgICAvLyBTb3J0IHRoZSB2YWx1ZXMgaW4gc2luZ2xlVGFibGUgc28gdGhhdCBhbGwgdGhlIHZhbHVlcyBmb3IgYSBnaXZlbiByb3cgYXJlIGdyb3VwZWRcbiAgICBDcmVhdGVSb3dzKCk7XG4gICAgLy9zZW5kcyB0aGUgZmlsdGVyaW5nIHF1ZXJ5IGFuZCB0aGVuIHJlIHJlbmRlcnMgdGhlIHRhYmxlIHdpdGggZmlsdGVyZWQgZGF0YVxuICAgICRzY29wZS5maWx0ZXIgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgZGF0YSkge1xuICAgICAgICBUYWJsZUZhY3RvcnkuZmlsdGVyKGRiTmFtZSwgdGFibGVOYW1lLCBkYXRhKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0LmRhdGE7XG4gICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgfSlcbiAgICB9XG5cblxuICAgICRzY29wZS5jaGVja0ZvcmVpZ24gPSBmdW5jdGlvbihjb2wpIHtcbiAgICAgICAgcmV0dXJuICRzY29wZS5mb3JlaWduQ29scy5oYXNPd25Qcm9wZXJ0eShjb2wpO1xuICAgIH1cblxuICAgICRzY29wZS5maW5kUHJpbWFyeSA9IFRhYmxlRmFjdG9yeS5maW5kUHJpbWFyeTtcblxuICAgIC8vKioqKioqKioqKioqIEltcG9ydGFudCAqKioqKioqKipcbiAgICAvLyBNYWtlIHN1cmUgdG8gdXBkYXRlIHRoZSByb3cgdmFsdWVzIEJFRk9SRSB0aGUgY29sdW1uIG5hbWVcbiAgICAvLyBUaGUgcm93VmFsc1RvVXBkYXRlIGFycmF5IHN0b3JlcyB0aGUgdmFsdWVzIG9mIHRoZSBPUklHSU5BTCBjb2x1bW4gbmFtZXMgc28gaWYgdGhlIGNvbHVtbiBuYW1lIGlzIHVwZGF0ZWQgYWZ0ZXIgdGhlIHJvdyB2YWx1ZSwgd2Ugc3RpbGwgaGF2ZSByZWZlcmVuY2UgdG8gd2hpY2ggY29sdW1uIHRoZSByb3cgdmFsdWUgcmVmZXJlbmNlc1xuXG5cbiAgICAvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vVXBkYXRpbmcgQ29sdW1uIFN0dWZmLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuXG4gICAgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZSA9IFtdO1xuXG4gICAgJHNjb3BlLnVwZGF0ZUNvbHVtbnMgPSBmdW5jdGlvbihvbGQsIG5ld0NvbE5hbWUsIGkpIHtcbiAgICAgICAgJHNjb3BlLmNvbHVtbnNbaV0gPSBuZXdDb2xOYW1lO1xuXG4gICAgICAgIHZhciBjb2xPYmogPSB7IG9sZFZhbDogJHNjb3BlLm9yaWdpbmFsQ29sVmFsc1tpXSwgbmV3VmFsOiBuZXdDb2xOYW1lIH07XG5cbiAgICAgICAgLy8gaWYgdGhlcmUgaXMgbm90aGluZyBpbiB0aGUgYXJyYXkgdG8gdXBkYXRlLCBwdXNoIHRoZSB1cGRhdGUgaW50byBpdFxuICAgICAgICBpZiAoJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZS5sZW5ndGggPT09IDApIHsgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZS5wdXNoKGNvbE9iaik7IH0gZWxzZSB7XG4gICAgICAgICAgICBmb3IgKHZhciBlID0gMDsgZSA8ICRzY29wZS5jb2xWYWxzVG9VcGRhdGUubGVuZ3RoOyBlKyspIHtcbiAgICAgICAgICAgICAgICBpZiAoJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZVtlXS5vbGRWYWwgPT09IGNvbE9iai5vbGRWYWwpIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZVtlXSA9IGNvbE9iajtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgICRzY29wZS5jb2xWYWxzVG9VcGRhdGUucHVzaChjb2xPYmopO1xuICAgICAgICB9XG4gICAgICAgIC8vIGNoZWNrIHRvIHNlZSBpZiB0aGUgcm93IGlzIGFscmVhZHkgc2NoZWR1bGVkIHRvIGJlIHVwZGF0ZWQsIGlmIGl0IGlzLCB0aGVuIHVwZGF0ZSBpdCB3aXRoIHRoZSBuZXcgdGhpbmcgdG8gYmUgdXBkYXRlZFxuICAgIH1cblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9VcGRhdGluZyBSb3cgU3R1ZmYvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG5cbiAgICAkc2NvcGUucm93VmFsc1RvVXBkYXRlID0gW107XG5cbiAgICAkc2NvcGUudXBkYXRlUm93ID0gZnVuY3Rpb24ob2xkLCBuZXdDZWxsLCByb3csIGksIGope1xuICAgICAgICB2YXIgY29scyA9ICRzY29wZS5vcmlnaW5hbENvbFZhbHM7XG4gICAgICAgIHZhciBmb3VuZCA9IGZhbHNlO1xuICAgICAgICB2YXIgY29sTmFtZSA9IGNvbHNbal07XG4gICAgICAgIGZvcih2YXIgayA9IDA7IGsgPCAkc2NvcGUucm93VmFsc1RvVXBkYXRlLmxlbmd0aDsgaysrKXtcbiAgICAgICAgICAgIHZhciBvYmogPSAkc2NvcGUucm93VmFsc1RvVXBkYXRlW2tdO1xuICAgICAgICAgICAgY29uc29sZS5sb2cob2JqKVxuICAgICAgICAgICAgaWYob2JqWydpZCddID09PSBpKXtcbiAgICAgICAgICAgICAgICBmb3VuZCA9IHRydWU7XG4gICAgICAgICAgICAgICAgaWYob2JqW2NvbE5hbWVdKSBvYmpbY29sTmFtZV0gPSBuZXdDZWxsO1xuICAgICAgICAgICAgICAgIG9ialtjb2xOYW1lXSA9IG5ld0NlbGw7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgaWYoIWZvdW5kKSB7XG4gICAgICAgICAgICB2YXIgcm93T2JqID0ge307XG4gICAgICAgICAgICByb3dPYmpbJ2lkJ10gPSBpO1xuICAgICAgICAgICAgcm93T2JqW2NvbE5hbWVdID0gbmV3Q2VsbDtcbiAgICAgICAgICAgICRzY29wZS5yb3dWYWxzVG9VcGRhdGUucHVzaChyb3dPYmopXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAkc2NvcGUudXBkYXRlQmFja2VuZCA9IGZ1bmN0aW9uKCkge1xuICAgICAgICB2YXIgZGF0YSA9IHsgcm93czogJHNjb3BlLnJvd1ZhbHNUb1VwZGF0ZSwgY29sdW1uczogJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZSB9XG4gICAgICAgIFRhYmxlRmFjdG9yeS51cGRhdGVCYWNrZW5kKCRzY29wZS50aGVEYk5hbWUsICRzY29wZS50aGVUYWJsZU5hbWUsIGRhdGEpO1xuICAgIH1cblxuXG4gICAgJHNjb3BlLmRlbGV0ZVRhYmxlID0gZnVuY3Rpb24oKSB7XG4gICAgICAgIFRhYmxlRmFjdG9yeS5kZWxldGVUYWJsZSgkc2NvcGUuY3VycmVudFRhYmxlKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgJHN0YXRlLmdvKCdUYWJsZScsIHsgZGJOYW1lOiAkc2NvcGUudGhlRGJOYW1lIH0sIHsgcmVsb2FkOiB0cnVlIH0pXG4gICAgICAgICAgICB9KVxuICAgIH1cblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9RdWVyeWluZyBTdHVmZi8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMgPSBbXTtcblxuICAgICRzY29wZS50YWJsZXNUb1F1ZXJ5ID0gW107XG5cbiAgICBhc3NvY2lhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgaWYgKHJvdy5UYWJsZTEgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9ucy5pbmRleE9mKHJvdy5UYWJsZTIpID09IC0xKSB7XG4gICAgICAgICAgICAkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zLnB1c2gocm93LlRhYmxlMik7XG4gICAgICAgIH0gZWxzZSBpZiAocm93LlRhYmxlMiA9PT0gJHNjb3BlLnRoZVRhYmxlTmFtZSAmJiAkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zLmluZGV4T2Yocm93LlRhYmxlMSkgPT0gLTEpIHtcbiAgICAgICAgICAgICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMucHVzaChyb3cuVGFibGUxKTtcbiAgICAgICAgfVxuICAgIH0pXG5cbiAgICAkc2NvcGUuZ2V0QXNzb2NpYXRlZCA9IGZ1bmN0aW9uKHZhbCkge1xuICAgICAgICBpZiAoJHNjb3BlLnRhYmxlc1RvUXVlcnkuaW5kZXhPZigkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zW3ZhbF0pID09PSAtMSkge1xuICAgICAgICAgICAgJHNjb3BlLnRhYmxlc1RvUXVlcnkucHVzaCgkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zW3ZhbF0pXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB2YXIgaSA9ICRzY29wZS50YWJsZXNUb1F1ZXJ5LmluZGV4T2YoJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9uc1t2YWxdKTtcbiAgICAgICAgICAgICRzY29wZS50YWJsZXNUb1F1ZXJ5LnNwbGljZShpLCAxKVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLmNvbHVtbnNGb3JRdWVyeSA9IFtdO1xuXG4gICAgJHNjb3BlLmdldENvbHVtbnNGb3JUYWJsZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgICB2YXIgcHJvbWlzZXNGb3JDb2x1bW5zID0gW107XG4gICAgICAgICRzY29wZS50YWJsZXNUb1F1ZXJ5LmZvckVhY2goZnVuY3Rpb24odGFibGVOYW1lKSB7XG4gICAgICAgICAgICByZXR1cm4gcHJvbWlzZXNGb3JDb2x1bW5zLnB1c2goVGFibGVGYWN0b3J5LmdldENvbHVtbnNGb3JUYWJsZSgkc2NvcGUudGhlRGJOYW1lLCB0YWJsZU5hbWUpKVxuICAgICAgICB9KVxuICAgICAgICBQcm9taXNlLmFsbChwcm9taXNlc0ZvckNvbHVtbnMpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihjb2x1bW5zKSB7XG4gICAgICAgICAgICAgICAgY29sdW1ucy5mb3JFYWNoKGZ1bmN0aW9uKGNvbHVtbikge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuY29sdW1uc0ZvclF1ZXJ5LnB1c2goY29sdW1uKTtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLiRldmFsQXN5bmMoKVxuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB9KVxuXG4gICAgfVxuXG4gICAgdmFyIHNlbGVjdGVkQ29sdW1ucyA9IHt9O1xuICAgIHZhciBxdWVyeVRhYmxlO1xuXG4gICAgJHNjb3BlLmdldERhdGFGcm9tQ29sdW1ucyA9IGZ1bmN0aW9uKHZhbCkge1xuICAgICAgICBpZighc2VsZWN0ZWRDb2x1bW5zKSBzZWxlY3RlZENvbHVtbnMgPSBbXTtcblxuICAgICAgICB2YXIgY29sdW1uTmFtZSA9ICRzY29wZS5jb2x1bW5zRm9yUXVlcnlbMF1bJ2NvbHVtbnMnXVt2YWwuaV07XG4gICAgICAgIHZhciB0YWJsZU5hbWUgPSB2YWwudGFibGVOYW1lXG4gICAgICAgIHF1ZXJ5VGFibGUgPSB0YWJsZU5hbWU7XG5cbiAgICAgICAgaWYgKCFzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXSkgc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0gPSBbXTtcbiAgICAgICAgaWYgKHNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdLmluZGV4T2YoY29sdW1uTmFtZSkgIT09IC0xKSB7XG4gICAgICAgICAgICBzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXS5zcGxpY2Uoc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0uaW5kZXhPZihjb2x1bW5OYW1lKSwgMSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdLnB1c2goY29sdW1uTmFtZSk7XG4gICAgICAgIH1cbiAgICAgICAgJHNjb3BlLnNlbGVjdGVkQ29sdW1ucyA9IHNlbGVjdGVkQ29sdW1ucztcbiAgICB9XG5cblxuICAgIC8vIFJ1bm5pbmcgdGhlIHF1ZXJ5ICsgcmVuZGVyaW5nIHRoZSBxdWVyeVxuICAgICRzY29wZS5yZXN1bHRPZlF1ZXJ5ID0gW107XG5cbiAgICAkc2NvcGUucXVlcnlSZXN1bHQ7XG5cbiAgICAkc2NvcGUuYXJyID0gW107XG5cblxuICAgIC8vIHRoZVRhYmxlTmFtZVxuXG4gICAgJHNjb3BlLnJ1bkpvaW4gPSBmdW5jdGlvbigpIHtcbiAgICAgICAgLy8gZGJOYW1lLCB0YWJsZTEsIGFycmF5T2ZUYWJsZXMsIHNlbGVjdGVkQ29sdW1ucywgYXNzb2NpYXRpb25zXG4gICAgICAgIHZhciBjb2x1bW5zVG9SZXR1cm4gPSAkc2NvcGUuY29sdW1ucy5tYXAoZnVuY3Rpb24oY29sTmFtZSl7XG4gICAgICAgICAgICByZXR1cm4gJHNjb3BlLnRoZVRhYmxlTmFtZSArICcuJyArIGNvbE5hbWU7XG4gICAgICAgIH0pXG4gICAgICAgIGZvcih2YXIgcHJvcCBpbiAkc2NvcGUuc2VsZWN0ZWRDb2x1bW5zKXtcbiAgICAgICAgICAgJHNjb3BlLnNlbGVjdGVkQ29sdW1uc1twcm9wXS5mb3JFYWNoKGZ1bmN0aW9uKGNvbCl7XG4gICAgICAgICAgICAgICAgY29sdW1uc1RvUmV0dXJuLnB1c2gocHJvcCArICcuJyArIGNvbClcbiAgICAgICAgICAgfSlcbiAgICAgICAgfVxuICAgICAgICBUYWJsZUZhY3RvcnkucnVuSm9pbigkc2NvcGUudGhlRGJOYW1lLCAkc2NvcGUudGhlVGFibGVOYW1lLCAkc2NvcGUudGFibGVzVG9RdWVyeSwgJHNjb3BlLnNlbGVjdGVkQ29sdW1ucywgJHNjb3BlLmFzc29jaWF0aW9ucywgY29sdW1uc1RvUmV0dXJuKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocXVlcnlSZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUucXVlcnlSZXN1bHQgPSBxdWVyeVJlc3VsdDtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAkc3RhdGUuZ28oJ1RhYmxlLlNpbmdsZS5xdWVyeScpO1xuICAgICAgICAgICAgfSlcbiAgICB9XG5cbiAgICAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQgPSB0cnVlO1xuXG4gICAgJHNjb3BlLm9wZW4gPSBmdW5jdGlvbiAoZGJOYW1lLCB0YmxOYW1lLCBjb2wsIGluZGV4KSB7XG5cbiAgICAgIHZhciBtb2RhbEluc3RhbmNlID0gJHVpYk1vZGFsLm9wZW4oe1xuICAgICAgICBhbmltYXRpb246ICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCxcbiAgICAgICAgYmFja2Ryb3A6IGZhbHNlLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL2Fzc29jaWF0aW9uLm1vZGFsLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnQXNzb2NpYXRpb25JbnN0YW5jZUN0cmwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgZm9yZWlnbkNvbHM6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiAkc2NvcGUuZm9yZWlnbkNvbHM7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBmb3JUYWJsZTogZnVuY3Rpb24oVGFibGVGYWN0b3J5KXtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKHRibE5hbWUpXG4gICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmZpbmRQcmltYXJ5KGRiTmFtZSwgdGJsTmFtZSk7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBmb3JUYWJsZU5hbWU6IGZ1bmN0aW9uKCl7XG4gICAgICAgICAgICByZXR1cm4gdGJsTmFtZTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIGN1cnJUYWJsZTogZnVuY3Rpb24oKXtcbiAgICAgICAgICAgIHJldHVybiAkc2NvcGUudGhlVGFibGVOYW1lXG4gICAgICAgICAgfSxcbiAgICAgICAgICBjb2xOYW1lOiBmdW5jdGlvbiAoKXtcbiAgICAgICAgICAgIHJldHVybiBjb2w7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBpZDE6IGZ1bmN0aW9uKCl7XG4gICAgICAgICAgICByZXR1cm4gaW5kZXg7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9KTtcblxuICAgICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKFwiQ0xPU0VEXCIpXG4gICAgICAgICRzY29wZS4kZXZhbEFzeW5jKCk7XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgJHNjb3BlLnRvZ2dsZUFuaW1hdGlvbiA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9ICEkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQ7XG4gICAgfTtcblxuICAgICRzY29wZS5maWx0ZXJlZFJvd3M9W107XG4gICAgJHNjb3BlLmN1cnJlbnRQYWdlPTE7XG4gICAgJHNjb3BlLm51bVBlclBhZ2U9MTA7XG4gICAgJHNjb3BlLm1heFNpemU9NTtcblxuICAgICRzY29wZS4kd2F0Y2goXCJjdXJyZW50UGFnZSArIG51bVBlclBhZ2VcIiwgZnVuY3Rpb24oKXtcbiAgICAgICAgdmFyIGJlZ2luID0gKCgkc2NvcGUuY3VycmVudFBhZ2UgLSAxKSAqICRzY29wZS5udW1QZXJQYWdlKTtcbiAgICAgICAgdmFyIGVuZCA9IGJlZ2luICsgJHNjb3BlLm51bVBlclBhZ2U7XG4gICAgICAgICRzY29wZS5maWx0ZXJlZFJvd3MgPSAkc2NvcGUuaW5zdGFuY2VBcnJheS5zbGljZShiZWdpbiwgZW5kKTtcbiAgICB9KVxuXG4gICAgJHNjb3BlLiR3YXRjaChcImluc3RhbmNlQXJyYXlcIiwgZnVuY3Rpb24oKXtcbiAgICAgICAgdmFyIGJlZ2luID0gKCgkc2NvcGUuY3VycmVudFBhZ2UgLSAxKSAqICRzY29wZS5udW1QZXJQYWdlKTtcbiAgICAgICAgdmFyIGVuZCA9IGJlZ2luICsgJHNjb3BlLm51bVBlclBhZ2U7XG4gICAgICAgICRzY29wZS5maWx0ZXJlZFJvd3MgPSAkc2NvcGUuaW5zdGFuY2VBcnJheS5zbGljZShiZWdpbiwgZW5kKTtcbiAgICB9KSAgICBcblxufSk7XG4iLCJhcHAuY29udHJvbGxlcignVGFibGVDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgYWxsVGFibGVzLCAkc3RhdGUsIFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zLCAkdWliTW9kYWwsIEhvbWVGYWN0b3J5LCBhc3NvY2lhdGlvbnMsIGFsbENvbHVtbnMpIHtcblxuXHQkc2NvcGUuYWxsVGFibGVzID0gYWxsVGFibGVzO1xuXG5cdCRzY29wZS5jb2x1bW5BcnJheSA9IFtdO1xuXG5cdCRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lXG5cblx0JHNjb3BlLmFzc29jaWF0aW9ucyA9IGFzc29jaWF0aW9ucztcblxuXHQkc2NvcGUuYWxsQ29sdW1ucyA9IGFsbENvbHVtbnM7XG5cblx0JHNjb3BlLmFzc29jaWF0aW9uVGFibGUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lICsgJ19hc3NvYyc7XG5cblx0JHNjb3BlLm51bVRhYmxlcyA9ICRzY29wZS5hbGxUYWJsZXMucm93cy5sZW5ndGg7XG5cblx0JHNjb3BlLmFkZCA9IGZ1bmN0aW9uKCkge1xuXHRcdCRzY29wZS5jb2x1bW5BcnJheS5wdXNoKCcxJyk7XG5cdH1cblxuXHQkc2NvcGUuJHN0YXRlID0gJHN0YXRlOyBcdC8vIHVzZWQgdG8gaGlkZSB0aGUgbGlzdCBvZiBhbGwgdGFibGVzIHdoZW4gaW4gc2luZ2xlIHRhYmxlIHN0YXRlXG5cblx0JHNjb3BlLmFzc29jaWF0aW9uVHlwZXMgPSBbJ2hhc09uZScsICdoYXNNYW55J107XG5cblx0JHNjb3BlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG5cblx0JHNjb3BlLnN1Ym1pdHRlZCA9IGZhbHNlO1xuXG5cdCRzY29wZS5tYWtlQXNzb2NpYXRpb25zID0gZnVuY3Rpb24oYXNzb2NpYXRpb24sIGRiTmFtZSkge1xuXHRcdCRzY29wZS5zdWJtaXR0ZWQgPSB0cnVlO1xuXHRcdFRhYmxlRmFjdG9yeS5tYWtlQXNzb2NpYXRpb25zKGFzc29jaWF0aW9uLCBkYk5hbWUpXG5cdFx0Ly8gLnRoZW4oZnVuY3Rpb24oKSB7XG5cdFx0Ly8gXHQkc3RhdGUuZ28oJ1RhYmxlJywge2RiTmFtZSA6ICRzY29wZS5kYk5hbWV9LCB7cmVsb2FkOnRydWV9KTtcblx0XHQvLyB9KVxuXHR9IFxuXG5cdCRzY29wZS53aGVyZWJldHdlZW4gPSBmdW5jdGlvbihjb25kaXRpb24pIHtcblx0XHRpZihjb25kaXRpb24gPT09IFwiV0hFUkUgQkVUV0VFTlwiIHx8IGNvbmRpdGlvbiA9PT0gXCJXSEVSRSBOT1QgQkVUV0VFTlwiKSByZXR1cm4gdHJ1ZTtcblx0fVxuXG5cdCRzY29wZS5jcmVhdGVUYWJsZSA9IGZ1bmN0aW9uKHRhYmxlKXtcblx0XHRUYWJsZUZhY3RvcnkuY3JlYXRlVGFibGUodGFibGUpXG5cdFx0LnRoZW4oZnVuY3Rpb24oKXtcblx0XHRcdCRzdGF0ZS5nbygnVGFibGUnLCB7ZGJOYW1lOiAkc2NvcGUuZGJOYW1lfSwge3JlbG9hZDogdHJ1ZX0pO1xuXHRcdH0pXG5cdH1cblxuXHQkc2NvcGUuY29sdW1uRGF0YVR5cGUgPSBmdW5jdGlvbigpIHtcblx0XHQkc2NvcGUuYWxsQ29sdW1ucy5mb3JFYWNoKGZ1bmN0aW9uKG9iaikge1xuXHRcdFx0aWYob2JqLnRhYmxlX25hbWUgPT09ICRzY29wZS5xdWVyeS50YWJsZTEgJiYgb2JqLmNvbHVtbl9uYW1lID09PSAkc2NvcGUucXVlcnkuY29sdW1uKSAkc2NvcGUudHlwZSA9IG9iai5kYXRhX3R5cGU7XG5cdFx0fSlcblx0fVxuXG5cdCRzY29wZS5zZWxlY3RlZEFzc29jID0ge307XG5cblx0Ly8gJHNjb3BlLmdldEFzc29jaWF0ZWQgPSBmdW5jdGlvbih0YWJsZU5hbWUpIHtcblx0Ly8gXHQkc2NvcGUuYXNzb2NpYXRpb25zLmZvckVhY2goZnVuY3Rpb24ocm93KXtcblx0Ly8gXHRcdGlmKCEkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdKXsgXG5cdC8vIFx0XHRcdCRzY29wZS5zZWxlY3RlZEFzc29jW3RhYmxlTmFtZV0gPSBbXTtcblx0Ly8gXHRcdH1cblx0Ly8gXHRcdGlmKHJvdy5UYWJsZTEgPT09IHRhYmxlTmFtZSAmJiAkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdLmluZGV4T2Yocm93LlRhYmxlMikgPT0gLTEpe1xuXHQvLyBcdFx0XHQkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdLnB1c2gocm93LlRhYmxlMik7XG5cdC8vIFx0XHR9XG5cdC8vIFx0XHRlbHNlIGlmKHJvdy5UYWJsZTIgPT09IHRhYmxlTmFtZSAmJiAkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdLmluZGV4T2Yocm93LlRhYmxlMSkgPT0gLTEpe1xuXHQvLyBcdFx0XHQkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdLnB1c2gocm93LlRhYmxlMSk7XHRcblx0Ly8gXHRcdH0gXG5cdC8vIFx0fSlcblx0Ly8gfVxuXG5cdC8vICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMgPSBbXTtcblxuXHQvLyBhc3NvY2lhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihyb3cpe1xuXHQvLyBcdGlmKHJvdy5UYWJsZTEgPT09IHRhYmxlTmFtZSAmJiAkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdLmluZGV4T2Yocm93LlRhYmxlMikgPT0gLTEpe1xuXHQvLyBcdFx0JHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9ucy5wdXNoKHJvdy5UYWJsZTIpO1xuXHQvLyBcdH1cblx0Ly8gXHRlbHNlIGlmKHJvdy5UYWJsZTIgPT09IHRhYmxlTmFtZSAmJiAkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdLmluZGV4T2Yocm93LlRhYmxlMSkgPT0gLTEpe1xuXHQvLyBcdFx0JHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXS5wdXNoKHJvdy5UYWJsZTEpO1x0XG5cdC8vIFx0fSBcblx0Ly8gfSlcblxuXHQkc2NvcGUuc3VibWl0UXVlcnkgPSBUYWJsZUZhY3Rvcnkuc3VibWl0UXVlcnk7XG5cbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ1RhYmxlRmFjdG9yeScsIGZ1bmN0aW9uICgkaHR0cCwgJHN0YXRlUGFyYW1zKSB7XG5cblx0dmFyIFRhYmxlRmFjdG9yeSA9IHt9O1xuXG5cdGZ1bmN0aW9uIHJlc1RvRGF0YShyZXMpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5kYXRhO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRBbGxUYWJsZXMgPSBmdW5jdGlvbihkYk5hbWUpe1xuICAgIFx0cmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lKVxuICAgIFx0LnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldERiTmFtZSA9IGZ1bmN0aW9uKGRiTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvbWFzdGVyZGIvJyArIGRiTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5maWx0ZXIgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgZGF0YSkge1xuICAgICAgICByZXR1cm4gJGh0dHAucHV0KCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnL2ZpbHRlcicsIGRhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LnVwZGF0ZUJhY2tlbmQgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgZGF0YSkge1xuICAgICAgICByZXR1cm4gJGh0dHAucHV0KCdhcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSwgZGF0YSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuYWRkUm93ID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIHJvd051bWJlcikge1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnYXBpL2NsaWVudGRiL2FkZHJvdy8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lLCB7cm93TnVtYmVyOiByb3dOdW1iZXJ9KVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVSb3cgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgcm93SWQsIGxlbmd0aCl7XG4gICAgICAgIHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSArICcvJyArIHJvd0lkICsgJy8nICsgbGVuZ3RoKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LnJlbW92ZUNvbHVtbiA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCBjb2x1bW5OYW1lKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmRlbGV0ZSgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lICsgJy9jb2x1bW4vJyArIGNvbHVtbk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuYWRkQ29sdW1uID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIG51bU5ld0NvbCl7XG4gICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCdhcGkvY2xpZW50ZGIvYWRkY29sdW1uLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnLycgKyBudW1OZXdDb2wpXG4gICAgfVxuICAgIFRhYmxlRmFjdG9yeS5jcmVhdGVUYWJsZSA9IGZ1bmN0aW9uKHRhYmxlKXtcbiAgICAgICAgdGFibGUuZGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZTtcbiAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9hcGkvY2xpZW50ZGInLCB0YWJsZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZGVsZXRlVGFibGUgPSBmdW5jdGlvbihjdXJyZW50VGFibGUpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmRlbGV0ZSgnL2FwaS9jbGllbnRkYi8nICsgY3VycmVudFRhYmxlLmRiTmFtZSArICcvJyArIGN1cnJlbnRUYWJsZS50YWJsZU5hbWUpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5Lm1ha2VBc3NvY2lhdGlvbnMgPSBmdW5jdGlvbihhc3NvY2lhdGlvbiwgZGJOYW1lKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnL2Fzc29jaWF0aW9uJywgYXNzb2NpYXRpb24pXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmRlbGV0ZURiID0gZnVuY3Rpb24oZGJOYW1lKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZ2V0QXNzb2NpYXRpb25zID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi9hc3NvY2lhdGlvbnRhYmxlLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgIFRhYmxlRmFjdG9yeS5nZXRBbGxBc3NvY2lhdGlvbnMgPSBmdW5jdGlvbihkYk5hbWUpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi9hbGxhc3NvY2lhdGlvbnMvJyArIGRiTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZ2V0QWxsQ29sdW1ucyA9IGZ1bmN0aW9uKGRiTmFtZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2NsaWVudGRiL2dldGFsbGNvbHVtbnMvJyArIGRiTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZ2V0Q29sdW1uc0ZvclRhYmxlID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2NsaWVudGRiL2NvbHVtbnNmb3J0YWJsZS8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5ydW5Kb2luID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZTEsIGFycmF5T2ZUYWJsZXMsIHNlbGVjdGVkQ29sdW1ucywgYXNzb2NpYXRpb25zLCBjb2xzVG9SZXR1cm4pIHtcbiAgICAgICAgdmFyIGRhdGEgPSB7fTtcbiAgICAgICAgZGF0YS5kYk5hbWUgPSBkYk5hbWU7XG4gICAgICAgIGRhdGEudGFibGUyID0gYXJyYXlPZlRhYmxlc1swXTtcbiAgICAgICAgZGF0YS5hcnJheU9mVGFibGVzID0gYXJyYXlPZlRhYmxlcztcbiAgICAgICAgZGF0YS5zZWxlY3RlZENvbHVtbnMgPSBzZWxlY3RlZENvbHVtbnM7XG4gICAgICAgIGRhdGEuY29sc1RvUmV0dXJuID0gY29sc1RvUmV0dXJuO1xuXG4gICAgICAgIC8vIFtoYXNNYW55LCBoYXNPbmUsIGhhc01hbnkgcHJpbWFyeSBrZXksIGhhc09uZSBmb3JnZWluIGtleV1cblxuICAgICAgICBhc3NvY2lhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIGlmKHJvdy5UYWJsZTEgPT09IHRhYmxlMSAmJiByb3cuVGFibGUyID09PSBkYXRhLnRhYmxlMil7XG4gICAgICAgICAgICAgICAgZGF0YS5hbGlhcyA9IHJvdy5BbGlhczE7XG4gICAgICAgICAgICAgICAgaWYocm93LlJlbGF0aW9uc2hpcDEgPT09ICdoYXNPbmUnKXtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTEgPSByb3cuVGFibGUyO1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMiA9IHJvdy5UYWJsZTE7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2V7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUxID0gcm93LlRhYmxlMTtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTIgPSByb3cuVGFibGUyOyAgIFxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2UgaWYocm93LlRhYmxlMSA9PT0gZGF0YS50YWJsZTIgJiYgcm93LlRhYmxlMiA9PT0gdGFibGUxKXtcbiAgICAgICAgICAgICAgICBkYXRhLmFsaWFzID0gcm93LkFsaWFzMTtcbiAgICAgICAgICAgICAgICBpZihyb3cuUmVsYXRpb25zaGlwMSA9PT0gJ2hhc01hbnknKXtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTEgPSByb3cuVGFibGUxO1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMiA9IHJvdy5UYWJsZTI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2V7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUxID0gcm93LlRhYmxlMjtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTIgPSByb3cuVGFibGUxOyAgIFxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfSlcblxuICAgICAgICByZXR1cm4gJGh0dHAucHV0KCcvYXBpL2NsaWVudGRiL3J1bmpvaW4nLCBkYXRhKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRQcmltYXJ5S2V5cyA9IGZ1bmN0aW9uKGlkLCBkYk5hbWUsIHRhYmxlTmFtZSwgY29sdW1ua2V5KXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lICsgJy8nICsgaWQgKyBcIi9cIiArIGNvbHVtbmtleSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZmluZFByaW1hcnkgPSBmdW5jdGlvbihkYk5hbWUsIHRibE5hbWUpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2NsaWVudGRiL3ByaW1hcnkvJytkYk5hbWUrJy8nK3RibE5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LnNldEZvcmVpZ25LZXkgPSBmdW5jdGlvbihkYk5hbWUsIHRibE5hbWUsIGNvbE5hbWUsIGlkMSwgaWQyKXtcbiAgICAgICAgdmFyIGRhdGEgPSB7fTtcbiAgICAgICAgZGF0YS5kYk5hbWUgPSBkYk5hbWU7XG4gICAgICAgIGRhdGEudGJsTmFtZSA9IHRibE5hbWU7XG4gICAgICAgIGRhdGEuY29sTmFtZSA9IGNvbE5hbWU7XG4gICAgICAgIGRhdGEuaWQxID0gaWQxO1xuICAgICAgICBkYXRhLmlkMiA9IGlkMjtcblxuICAgICAgICByZXR1cm4gJGh0dHAucHV0KCcvYXBpL2NsaWVudGRiL3NldEZvcmVpZ25LZXknLCBkYXRhKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpOyAgIFxuICAgIH1cblxuXHRyZXR1cm4gVGFibGVGYWN0b3J5OyBcbn0pIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUnLCB7XG4gICAgICAgIHVybDogJy86ZGJOYW1lJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS90YWJsZS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1RhYmxlQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgXHRhbGxUYWJsZXM6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRBbGxUYWJsZXMoJHN0YXRlUGFyYW1zLmRiTmFtZSk7XG4gICAgICAgIFx0fSwgXG4gICAgICAgICAgICBhc3NvY2lhdGlvbnM6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRBbGxBc3NvY2lhdGlvbnMoJHN0YXRlUGFyYW1zLmRiTmFtZSk7XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgYWxsQ29sdW1uczogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldEFsbENvbHVtbnMoJHN0YXRlUGFyYW1zLmRiTmFtZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KTtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5TaW5nbGUnLCB7XG4gICAgICAgIHVybDogJy86dGFibGVOYW1lJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9zaW5nbGV0YWJsZS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1NpbmdsZVRhYmxlQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICAgIHNpbmdsZVRhYmxlOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0U2luZ2xlVGFibGUoJHN0YXRlUGFyYW1zLmRiTmFtZSwgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSk7XG4gICAgICAgICAgICB9LCBcbiAgICAgICAgICAgIGFzc29jaWF0aW9uczogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldEFzc29jaWF0aW9ucygkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pO1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlLkpvaW4nLCB7XG4gICAgICAgIHVybDogJy86dGFibGVOYW1lLzpyb3dJZC86a2V5L2pvaW4nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL2pvaW4uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdKb2luVGFibGVDdHJsJyxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICAgICAgam9pblRhYmxlOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0UHJpbWFyeUtleXMoJHN0YXRlUGFyYW1zLnJvd0lkLCAkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lLCAkc3RhdGVQYXJhbXMua2V5KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pO1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlLmNyZWF0ZScsIHtcbiAgICAgICAgdXJsOiAnL2NyZWF0ZXRhYmxlJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9jcmVhdGV0YWJsZS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1RhYmxlQ3RybCdcbiAgICB9KTtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5zZXRBc3NvY2lhdGlvbicsIHtcbiAgICAgICAgdXJsOiAnL3NldGFzc29jaWF0aW9uJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9zZXRhc3NvY2lhdGlvbi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1RhYmxlQ3RybCdcbiAgICB9KTtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5TaW5nbGUucXVlcnknLCB7XG4gICAgICAgIHVybDogJy9xdWVyeXJlc3VsdCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvcXVlcnkuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdRdWVyeVRhYmxlQ3RybCdcbiAgICB9KTsgICAgIFxuXG59KTsiLCJhcHAuZmFjdG9yeSgnRnVsbHN0YWNrUGljcycsIGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4gW1xuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I3Z0JYdWxDQUFBWFFjRS5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9mYmNkbi1zcGhvdG9zLWMtYS5ha2FtYWloZC5uZXQvaHBob3Rvcy1hay14YXAxL3QzMS4wLTgvMTA4NjI0NTFfMTAyMDU2MjI5OTAzNTkyNDFfODAyNzE2ODg0MzMxMjg0MTEzN19vLmpwZycsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQi1MS1VzaElnQUV5OVNLLmpwZycsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQjc5LVg3b0NNQUFrdzd5LmpwZycsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQi1VajlDT0lJQUlGQWgwLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQjZ5SXlGaUNFQUFxbDEyLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0UtVDc1bFdBQUFtcXFKLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0V2WkFnLVZBQUFrOTMyLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0VnTk1lT1hJQUlmRGhLLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0VReUlETldnQUF1NjBCLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0NGM1Q1UVc4QUUybEdKLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0FlVnc1U1dvQUFBTHNqLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0FhSklQN1VrQUFsSUdzLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0FRT3c5bFdFQUFZOUZsLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQi1PUWJWckNNQUFOd0lNLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQjliX2Vyd0NZQUF3UmNKLnBuZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQjVQVGR2bkNjQUVBbDR4LmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQjRxd0MwaUNZQUFsUEdoLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQjJiMzN2UklVQUE5bzFELmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQndwSXdyMUlVQUF2TzJfLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQnNTc2VBTkNZQUVPaEx3LmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0o0dkxmdVV3QUFkYTRMLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0k3d3pqRVZFQUFPUHBTLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0lkSHZUMlVzQUFubkhWLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0dDaVBfWVdZQUFvNzVWLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQ0lTNEpQSVdJQUkzN3F1LmpwZzpsYXJnZSdcbiAgICBdO1xufSk7XG4iLCJhcHAuZmFjdG9yeSgnUmFuZG9tR3JlZXRpbmdzJywgZnVuY3Rpb24gKCkge1xuXG4gICAgdmFyIGdldFJhbmRvbUZyb21BcnJheSA9IGZ1bmN0aW9uIChhcnIpIHtcbiAgICAgICAgcmV0dXJuIGFycltNYXRoLmZsb29yKE1hdGgucmFuZG9tKCkgKiBhcnIubGVuZ3RoKV07XG4gICAgfTtcblxuICAgIHZhciBncmVldGluZ3MgPSBbXG4gICAgICAgICdIZWxsbywgd29ybGQhJyxcbiAgICAgICAgJ0F0IGxvbmcgbGFzdCwgSSBsaXZlIScsXG4gICAgICAgICdIZWxsbywgc2ltcGxlIGh1bWFuLicsXG4gICAgICAgICdXaGF0IGEgYmVhdXRpZnVsIGRheSEnLFxuICAgICAgICAnSVxcJ20gbGlrZSBhbnkgb3RoZXIgcHJvamVjdCwgZXhjZXB0IHRoYXQgSSBhbSB5b3Vycy4gOiknLFxuICAgICAgICAnVGhpcyBlbXB0eSBzdHJpbmcgaXMgZm9yIExpbmRzYXkgTGV2aW5lLicsXG4gICAgICAgICfjgZPjgpPjgavjgaHjga/jgIHjg6bjg7zjgrbjg7zmp5jjgIInLFxuICAgICAgICAnV2VsY29tZS4gVG8uIFdFQlNJVEUuJyxcbiAgICAgICAgJzpEJyxcbiAgICAgICAgJ1llcywgSSB0aGluayB3ZVxcJ3ZlIG1ldCBiZWZvcmUuJyxcbiAgICAgICAgJ0dpbW1lIDMgbWlucy4uLiBJIGp1c3QgZ3JhYmJlZCB0aGlzIHJlYWxseSBkb3BlIGZyaXR0YXRhJyxcbiAgICAgICAgJ0lmIENvb3BlciBjb3VsZCBvZmZlciBvbmx5IG9uZSBwaWVjZSBvZiBhZHZpY2UsIGl0IHdvdWxkIGJlIHRvIG5ldlNRVUlSUkVMIScsXG4gICAgXTtcblxuICAgIHJldHVybiB7XG4gICAgICAgIGdyZWV0aW5nczogZ3JlZXRpbmdzLFxuICAgICAgICBnZXRSYW5kb21HcmVldGluZzogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuIGdldFJhbmRvbUZyb21BcnJheShncmVldGluZ3MpO1xuICAgICAgICB9XG4gICAgfTtcblxufSk7XG4iLCJhcHAuZGlyZWN0aXZlKCdzaWRlYmFyJywgZnVuY3Rpb24gKCRyb290U2NvcGUsIEF1dGhTZXJ2aWNlLCBBVVRIX0VWRU5UUywgJHN0YXRlKSB7XG5cbiAgICByZXR1cm4ge1xuICAgICAgICByZXN0cmljdDogJ0UnLFxuICAgICAgICBzY29wZToge30sXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvY29tbW9uL2RpcmVjdGl2ZXMvbmF2YmFyL25hdmJhci5odG1sJyxcbiAgICAgICAgbGluazogZnVuY3Rpb24gKHNjb3BlKSB7XG5cbiAgICAgICAgICAgIHNjb3BlLml0ZW1zID0gW1xuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdIb21lJywgc3RhdGU6ICdob21lJyB9LFxuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdBYm91dCcsIHN0YXRlOiAnYWJvdXQnIH0sXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ0RvY3VtZW50YXRpb24nLCBzdGF0ZTogJ2RvY3MnIH0sXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ01lbWJlcnMgT25seScsIHN0YXRlOiAnbWVtYmVyc09ubHknLCBhdXRoOiB0cnVlIH1cbiAgICAgICAgICAgIF07XG5cbiAgICAgICAgICAgIHNjb3BlLnVzZXIgPSBudWxsO1xuXG4gICAgICAgICAgICBzY29wZS5pc0xvZ2dlZEluID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBBdXRoU2VydmljZS5pc0F1dGhlbnRpY2F0ZWQoKTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHNjb3BlLmxvZ291dCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBBdXRoU2VydmljZS5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAkc3RhdGUuZ28oJ2xhbmRpbmdQYWdlJyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICB2YXIgc2V0VXNlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKS50aGVuKGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgICAgICAgICAgIHNjb3BlLnVzZXIgPSB1c2VyO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgdmFyIHJlbW92ZVVzZXIgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgc2NvcGUudXNlciA9IG51bGw7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICBzZXRVc2VyKCk7XG5cbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLmxvZ2luU3VjY2Vzcywgc2V0VXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5sb2dvdXRTdWNjZXNzLCByZW1vdmVVc2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LCByZW1vdmVVc2VyKTtcblxuICAgICAgICB9XG5cbiAgICB9O1xuXG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ2Z1bGxzdGFja0xvZ28nLCBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIHtcbiAgICAgICAgcmVzdHJpY3Q6ICdFJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9mdWxsc3RhY2stbG9nby9mdWxsc3RhY2stbG9nby5odG1sJ1xuICAgIH07XG59KTsiLCJhcHAuZGlyZWN0aXZlKCdyYW5kb0dyZWV0aW5nJywgZnVuY3Rpb24gKFJhbmRvbUdyZWV0aW5ncykge1xuXG4gICAgcmV0dXJuIHtcbiAgICAgICAgcmVzdHJpY3Q6ICdFJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9yYW5kby1ncmVldGluZy9yYW5kby1ncmVldGluZy5odG1sJyxcbiAgICAgICAgbGluazogZnVuY3Rpb24gKHNjb3BlKSB7XG4gICAgICAgICAgICBzY29wZS5ncmVldGluZyA9IFJhbmRvbUdyZWV0aW5ncy5nZXRSYW5kb21HcmVldGluZygpO1xuICAgICAgICB9XG4gICAgfTtcblxufSk7Il0sInNvdXJjZVJvb3QiOiIvc291cmNlLyJ9
