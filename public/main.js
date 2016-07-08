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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcC5qcyIsImFib3V0L2Fib3V0LmpzIiwiY3JlYXRlREIvY3JlYXRlREIuY29udHJvbGxlci5qcyIsImNyZWF0ZURCL2NyZWF0ZURCLmZhY3RvcnkuanMiLCJjcmVhdGVEQi9jcmVhdGVEQi5zdGF0ZS5qcyIsImRvY3MvZG9jcy5qcyIsImZzYS9mc2EtcHJlLWJ1aWx0LmpzIiwiaG9tZS9ob21lLmNvbnRyb2xsZXIuanMiLCJob21lL2hvbWUuZmFjdG9yeS5qcyIsImhvbWUvaG9tZS5zdGF0ZS5qcyIsImxhbmRpbmdQYWdlL2xhbmRpbmdQYWdlLnN0YXRlLmpzIiwibG9naW4vbG9naW4uanMiLCJtZW1iZXJzLW9ubHkvbWVtYmVycy1vbmx5LmpzIiwib2F1dGgvb2F1dGgtYnV0dG9uLmRpcmVjdGl2ZS5qcyIsInNpZ251cC9zaWdudXAuanMiLCJ0YWJsZS9hc3NvY2lhdGlvbi5jb250cm9sbGVyLmpzIiwidGFibGUvZGVsZXRlREJNb2RhbC5qcyIsInRhYmxlL2RlbGV0ZVRhYmxlTW9kYWwuanMiLCJ0YWJsZS9qb2luLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS9xdWVyeS5jb250cm9sbGVyLmpzIiwidGFibGUvc2luZ2xldGFibGUuY29udHJvbGxlci5qcyIsInRhYmxlL3RhYmxlLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS90YWJsZS5mYWN0b3J5LmpzIiwidGFibGUvdGFibGUuc3RhdGUuanMiLCJjb21tb24vZmFjdG9yaWVzL0Z1bGxzdGFja1BpY3MuanMiLCJjb21tb24vZmFjdG9yaWVzL1JhbmRvbUdyZWV0aW5ncy5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL2Z1bGxzdGFjay1sb2dvL2Z1bGxzdGFjay1sb2dvLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvbmF2YmFyL25hdmJhci5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL3JhbmRvLWdyZWV0aW5nL3JhbmRvLWdyZWV0aW5nLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOztBQUNBLE9BQUEsR0FBQSxHQUFBLFFBQUEsTUFBQSxDQUFBLHVCQUFBLEVBQUEsQ0FBQSxhQUFBLEVBQUEsV0FBQSxFQUFBLGNBQUEsRUFBQSxXQUFBLENBQUEsQ0FBQTs7QUFFQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGtCQUFBLEVBQUEsaUJBQUEsRUFBQTs7QUFFQSxzQkFBQSxTQUFBLENBQUEsSUFBQTs7QUFFQSx1QkFBQSxTQUFBLENBQUEsR0FBQTs7QUFFQSx1QkFBQSxJQUFBLENBQUEsaUJBQUEsRUFBQSxZQUFBO0FBQ0EsZUFBQSxRQUFBLENBQUEsTUFBQTtBQUNBLEtBRkE7QUFHQSxDQVRBOzs7QUFZQSxJQUFBLEdBQUEsQ0FBQSxVQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUEsTUFBQSxFQUFBOzs7QUFHQSxRQUFBLCtCQUFBLFNBQUEsNEJBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxJQUFBLE1BQUEsSUFBQSxDQUFBLFlBQUE7QUFDQSxLQUZBOzs7O0FBTUEsZUFBQSxHQUFBLENBQUEsbUJBQUEsRUFBQSxVQUFBLEtBQUEsRUFBQSxPQUFBLEVBQUEsUUFBQSxFQUFBOztBQUVBLFlBQUEsQ0FBQSw2QkFBQSxPQUFBLENBQUEsRUFBQTs7O0FBR0E7QUFDQTs7QUFFQSxZQUFBLFlBQUEsZUFBQSxFQUFBLEVBQUE7OztBQUdBO0FBQ0E7OztBQUdBLGNBQUEsY0FBQTs7QUFFQSxvQkFBQSxlQUFBLEdBQUEsSUFBQSxDQUFBLFVBQUEsSUFBQSxFQUFBOzs7O0FBSUEsZ0JBQUEsSUFBQSxFQUFBO0FBQ0EsdUJBQUEsRUFBQSxDQUFBLFFBQUEsSUFBQSxFQUFBLFFBQUE7QUFDQSxhQUZBLE1BRUE7QUFDQSx1QkFBQSxFQUFBLENBQUEsT0FBQTtBQUNBO0FBQ0EsU0FUQTtBQVdBLEtBNUJBO0FBOEJBLENBdkNBOztBQ2ZBLElBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBOzs7QUFHQSxtQkFBQSxLQUFBLENBQUEsT0FBQSxFQUFBO0FBQ0EsYUFBQSxRQURBO0FBRUEsb0JBQUEsaUJBRkE7QUFHQSxx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LElBQUEsRUFBQTtBQUNBLHVCQUFBLEdBQUEsSUFBQSxDQUFBLFFBQUEsSUFBQSxDQUFBO0FBQ0E7Ozs7O0FBS0EsbUJBQUEsTUFBQSxHQUFBLENBQUEsVUFBQSxFQUFBLElBQUEsQ0FBQSxpQkFBQSxFQUFBLEtBQUEsQ0FBQSxZQUFBO0FBQ0EsdUJBQUEsSUFBQTtBQUNBLGFBRkEsQ0FBQTtBQUlBLFNBckJBOztBQXVCQSxhQUFBLE1BQUEsR0FBQSxVQUFBLFdBQUEsRUFBQTtBQUNBLG1CQUFBLE1BQUEsSUFBQSxDQUFBLFNBQUEsRUFBQSxXQUFBLEVBQ0EsSUFEQSxDQUNBLGlCQURBLEVBRUEsS0FGQSxDQUVBLFlBQUE7QUFDQSx1QkFBQSxHQUFBLE1BQUEsQ0FBQSxFQUFBLFNBQUEsNkJBQUEsRUFBQSxDQUFBO0FBQ0EsYUFKQSxDQUFBO0FBS0EsU0FOQTs7QUFRQSxhQUFBLEtBQUEsR0FBQSxVQUFBLFdBQUEsRUFBQTtBQUNBLG1CQUFBLE1BQUEsSUFBQSxDQUFBLFFBQUEsRUFBQSxXQUFBLEVBQ0EsSUFEQSxDQUNBLGlCQURBLEVBRUEsS0FGQSxDQUVBLFlBQUE7QUFDQSx1QkFBQSxHQUFBLE1BQUEsQ0FBQSxFQUFBLFNBQUEsNEJBQUEsRUFBQSxDQUFBO0FBQ0EsYUFKQSxDQUFBO0FBS0EsU0FOQTs7QUFRQSxhQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsbUJBQUEsTUFBQSxHQUFBLENBQUEsU0FBQSxFQUFBLElBQUEsQ0FBQSxZQUFBO0FBQ0Esd0JBQUEsT0FBQTtBQUNBLDJCQUFBLFVBQUEsQ0FBQSxZQUFBLGFBQUE7QUFDQSxhQUhBLENBQUE7QUFJQSxTQUxBO0FBT0EsS0E3REE7O0FBK0RBLFFBQUEsT0FBQSxDQUFBLFNBQUEsRUFBQSxVQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUE7O0FBRUEsWUFBQSxPQUFBLElBQUE7O0FBRUEsbUJBQUEsR0FBQSxDQUFBLFlBQUEsZ0JBQUEsRUFBQSxZQUFBO0FBQ0EsaUJBQUEsT0FBQTtBQUNBLFNBRkE7O0FBSUEsbUJBQUEsR0FBQSxDQUFBLFlBQUEsY0FBQSxFQUFBLFlBQUE7QUFDQSxpQkFBQSxPQUFBO0FBQ0EsU0FGQTs7QUFJQSxhQUFBLEVBQUEsR0FBQSxJQUFBO0FBQ0EsYUFBQSxJQUFBLEdBQUEsSUFBQTs7QUFFQSxhQUFBLE1BQUEsR0FBQSxVQUFBLFNBQUEsRUFBQSxJQUFBLEVBQUE7QUFDQSxpQkFBQSxFQUFBLEdBQUEsU0FBQTtBQUNBLGlCQUFBLElBQUEsR0FBQSxJQUFBO0FBQ0EsU0FIQTs7QUFLQSxhQUFBLE9BQUEsR0FBQSxZQUFBO0FBQ0EsaUJBQUEsRUFBQSxHQUFBLElBQUE7QUFDQSxpQkFBQSxJQUFBLEdBQUEsSUFBQTtBQUNBLFNBSEE7QUFLQSxLQXpCQTtBQTJCQSxDQTVJQTs7QUNBQSxJQUFBLFVBQUEsQ0FBQSxVQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBLE1BQUEsRUFBQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxNQUFBO0FBQ0EsQ0FIQTs7QUNBQSxJQUFBLE9BQUEsQ0FBQSxhQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUE7O0FBRUEsUUFBQSxjQUFBLEVBQUE7O0FBRUEsYUFBQSxTQUFBLENBQUEsR0FBQSxFQUFBO0FBQ0EsZUFBQSxJQUFBLElBQUE7QUFDQTs7QUFFQSxnQkFBQSxTQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsZUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGdCQUFBLFFBQUEsR0FBQSxVQUFBLElBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsSUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLFdBQUEsV0FBQTtBQUNBLENBbkJBO0FDQUEsSUFBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxtQkFBQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsYUFBQSxPQURBO0FBRUEscUJBQUEsbUJBRkE7QUFHQSxvQkFBQSxVQUhBO0FBSUEsaUJBQUE7QUFDQSxvQkFBQSxnQkFBQSxXQUFBLEVBQUE7QUFDQSx1QkFBQSxZQUFBLFNBQUEsRUFBQTtBQUNBLGFBSEE7QUFJQSwwQkFBQSxzQkFBQSxXQUFBLEVBQUE7QUFDQSx1QkFBQSxZQUFBLGVBQUEsRUFBQTtBQUNBO0FBTkE7QUFKQSxLQUFBO0FBYUEsQ0FkQTtBQ0FBLElBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0EsbUJBQUEsS0FBQSxDQUFBLGFBQUEsRUFBQTtBQUNBLGFBQUEsR0FEQTtBQUVBLHFCQUFBO0FBRkEsS0FBQTtBQU1BLENBUEE7QUNBQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTs7QUFFQSxtQkFBQSxLQUFBLENBQUEsT0FBQSxFQUFBO0FBQ0EsYUFBQSxRQURBO0FBRUEscUJBQUEscUJBRkE7QUFHQSxvQkFBQTtBQUhBLEtBQUE7QUFNQSxDQVJBOztBQVVBLElBQUEsVUFBQSxDQUFBLFdBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxXQUFBLEVBQUEsTUFBQSxFQUFBOztBQUVBLFdBQUEsS0FBQSxHQUFBLEVBQUE7QUFDQSxXQUFBLEtBQUEsR0FBQSxJQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLFVBQUEsU0FBQSxFQUFBOztBQUVBLGVBQUEsS0FBQSxHQUFBLElBQUE7O0FBRUEsb0JBQUEsS0FBQSxDQUFBLFNBQUEsRUFBQSxJQUFBLENBQUEsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxNQUFBO0FBQ0EsU0FGQSxFQUVBLEtBRkEsQ0FFQSxZQUFBO0FBQ0EsbUJBQUEsS0FBQSxHQUFBLDRCQUFBO0FBQ0EsU0FKQTtBQU1BLEtBVkE7QUFZQSxDQWpCQTs7QUNWQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTs7QUFFQSxtQkFBQSxLQUFBLENBQUEsYUFBQSxFQUFBO0FBQ0EsYUFBQSxlQURBO0FBRUEsa0JBQUEsbUVBRkE7QUFHQSxvQkFBQSxvQkFBQSxNQUFBLEVBQUEsV0FBQSxFQUFBO0FBQ0Esd0JBQUEsUUFBQSxHQUFBLElBQUEsQ0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLHVCQUFBLEtBQUEsR0FBQSxLQUFBO0FBQ0EsYUFGQTtBQUdBLFNBUEE7OztBQVVBLGNBQUE7QUFDQSwwQkFBQTtBQURBO0FBVkEsS0FBQTtBQWVBLENBakJBOztBQW1CQSxJQUFBLE9BQUEsQ0FBQSxhQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUE7O0FBRUEsUUFBQSxXQUFBLFNBQUEsUUFBQSxHQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSwyQkFBQSxFQUFBLElBQUEsQ0FBQSxVQUFBLFFBQUEsRUFBQTtBQUNBLG1CQUFBLFNBQUEsSUFBQTtBQUNBLFNBRkEsQ0FBQTtBQUdBLEtBSkE7O0FBTUEsV0FBQTtBQUNBLGtCQUFBO0FBREEsS0FBQTtBQUlBLENBWkE7QUNuQkE7O0FBRUEsSUFBQSxTQUFBLENBQUEsYUFBQSxFQUFBLFlBQUE7QUFDQSxXQUFBO0FBQ0EsZUFBQTtBQUNBLDBCQUFBO0FBREEsU0FEQTtBQUlBLGtCQUFBLEdBSkE7QUFLQSxxQkFBQTtBQUxBLEtBQUE7QUFPQSxDQVJBOztBQ0ZBLElBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBOztBQUVBLG1CQUFBLEtBQUEsQ0FBQSxRQUFBLEVBQUE7QUFDQSxhQUFBLFNBREE7QUFFQSxxQkFBQSx1QkFGQTtBQUdBLG9CQUFBO0FBSEEsS0FBQTtBQU1BLENBUkE7O0FBVUEsSUFBQSxVQUFBLENBQUEsWUFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsRUFBQTtBQUNBLFdBQUEsS0FBQSxHQUFBLElBQUE7O0FBRUEsV0FBQSxVQUFBLEdBQUEsVUFBQSxVQUFBLEVBQUE7QUFDQSxlQUFBLEtBQUEsR0FBQSxJQUFBO0FBQ0Esb0JBQUEsTUFBQSxDQUFBLFVBQUEsRUFBQSxJQUFBLENBQUEsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxNQUFBO0FBQ0EsU0FGQSxFQUVBLEtBRkEsQ0FFQSxZQUFBO0FBQ0EsbUJBQUEsS0FBQSxHQUFBLDhDQUFBO0FBQ0EsU0FKQTtBQU1BLEtBUkE7QUFVQSxDQWZBOztBQ1ZBLElBQUEsVUFBQSxDQUFBLHlCQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsaUJBQUEsRUFBQSxXQUFBLEVBQUEsWUFBQSxFQUFBLFdBQUEsRUFBQSxZQUFBLEVBQUEsTUFBQSxFQUFBLFFBQUEsRUFBQSxZQUFBLEVBQUEsU0FBQSxFQUFBLE9BQUEsRUFBQSxHQUFBLEVBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBOztBQUVBLFdBQUEsV0FBQSxHQUFBLFFBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsWUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxTQUFBOztBQUVBLFdBQUEsT0FBQSxHQUFBLE9BQUE7O0FBRUEsV0FBQSxHQUFBLEdBQUEsR0FBQTs7QUFFQSxXQUFBLFdBQUEsR0FBQSxZQUFBOztBQUVBLGVBQUEsT0FBQSxHQUFBLEtBQUEsR0FBQTtBQUNBLGdCQUFBLEdBQUEsQ0FBQSxPQUFBLE9BQUE7QUFDQSxLQUpBOztBQVFBLGFBQUEsYUFBQSxHQUFBO0FBQ0EsZUFBQSxPQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsUUFBQSxTQUFBLENBQUEsQ0FBQTs7QUFHQSxhQUFBLElBQUEsSUFBQSxJQUFBLEtBQUEsRUFBQTtBQUNBLGdCQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxJQUFBO0FBQ0E7QUFDQTtBQUNBOztBQUVBOzs7QUFJQSxhQUFBLFVBQUEsR0FBQTtBQUNBLGVBQUEsYUFBQSxHQUFBLEVBQUE7QUFDQSxpQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxZQUFBLEVBQUE7QUFDQSxpQkFBQSxJQUFBLElBQUEsSUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxTQUFBLFlBQUEsSUFBQSxTQUFBLFlBQUEsRUFBQSxVQUFBLElBQUEsQ0FBQSxJQUFBLElBQUEsQ0FBQTtBQUNBO0FBQ0EsbUJBQUEsYUFBQSxDQUFBLElBQUEsQ0FBQSxTQUFBO0FBQ0EsU0FOQTtBQU9BOzs7QUFHQTs7QUFHQSxXQUFBLGFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxPQUFBLEVBQUEsT0FBQSxFQUFBLEdBQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSwwQkFBQSxLQUFBO0FBQ0EscUJBQUEsYUFBQSxDQUFBLE1BQUEsRUFBQSxPQUFBLEVBQUEsT0FBQSxFQUFBLEdBQUEsRUFBQSxHQUFBLEVBQ0EsSUFEQSxDQUNBLFlBQUE7QUFDQSxtQkFBQSxFQUFBLENBQUEsY0FBQSxFQUFBLEVBQUEsUUFBQSxPQUFBLE1BQUEsRUFBQSxXQUFBLE9BQUEsU0FBQSxFQUFBLEVBQUEsRUFBQSxRQUFBLElBQUEsRUFBQTtBQUNBLFNBSEE7QUFJQSxLQU5BOztBQVVBLFdBQUEsRUFBQSxHQUFBLFlBQUE7QUFDQSwwQkFBQSxLQUFBLENBQUEsT0FBQSxRQUFBLENBQUEsSUFBQTtBQUNBLEtBRkE7O0FBSUEsV0FBQSxNQUFBLEdBQUEsWUFBQTtBQUNBLDBCQUFBLE9BQUEsQ0FBQSxRQUFBO0FBQ0EsS0FGQTtBQUdBLENBdEVBO0FDQUEsSUFBQSxVQUFBLENBQUEsY0FBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxJQUFBLEVBQUE7O0FBRUEsV0FBQSxLQUFBLEdBQUEsQ0FBQSxPQUFBLEVBQUEsT0FBQSxFQUFBLE9BQUEsQ0FBQTs7QUFFQSxXQUFBLGlCQUFBLEdBQUEsSUFBQTs7QUFFQSxXQUFBLElBQUEsR0FBQSxVQUFBLElBQUEsRUFBQTs7QUFFQSxZQUFBLGdCQUFBLFVBQUEsSUFBQSxDQUFBO0FBQ0EsdUJBQUEsT0FBQSxpQkFEQTtBQUVBLHlCQUFBLHNCQUZBO0FBR0Esd0JBQUEsc0JBSEE7QUFJQSxrQkFBQSxJQUpBO0FBS0EscUJBQUE7QUFDQSx1QkFBQSxpQkFBQTtBQUNBLDJCQUFBLE9BQUEsS0FBQTtBQUNBO0FBSEE7QUFMQSxTQUFBLENBQUE7O0FBWUEsc0JBQUEsTUFBQSxDQUFBLElBQUEsQ0FBQSxVQUFBLFlBQUEsRUFBQTtBQUNBLG1CQUFBLFFBQUEsR0FBQSxZQUFBO0FBQ0EsU0FGQSxFQUVBLFlBQUE7QUFDQSxpQkFBQSxJQUFBLENBQUEseUJBQUEsSUFBQSxJQUFBLEVBQUE7QUFDQSxTQUpBO0FBS0EsS0FuQkE7O0FBcUJBLFdBQUEsZUFBQSxHQUFBLFlBQUE7QUFDQSxlQUFBLGlCQUFBLEdBQUEsQ0FBQSxPQUFBLGlCQUFBO0FBQ0EsS0FGQTtBQUlBLENBL0JBOztBQWlDQSxJQUFBLFVBQUEsQ0FBQSxzQkFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLGlCQUFBLEVBQUEsS0FBQSxFQUFBLFlBQUEsRUFBQSxXQUFBLEVBQUEsWUFBQSxFQUFBLE1BQUEsRUFBQTs7QUFHQSxXQUFBLFVBQUEsR0FBQSxlQUFBO0FBQ0EsV0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBOztBQUVBLFdBQUEsV0FBQSxHQUFBLFlBQUE7QUFDQSwwQkFBQSxLQUFBLENBQUEsT0FBQSxRQUFBLENBQUEsSUFBQTtBQUNBLHFCQUFBLFFBQUEsQ0FBQSxPQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsWUFBQTtBQUNBLHdCQUFBLFFBQUEsQ0FBQSxPQUFBLE1BQUE7QUFDQSxTQUhBLEVBSUEsSUFKQSxDQUlBLFlBQUE7QUFDQSxtQkFBQSxFQUFBLENBQUEsTUFBQSxFQUFBLEVBQUEsRUFBQSxFQUFBLFFBQUEsSUFBQSxFQUFBO0FBQ0EsU0FOQTtBQU9BLEtBVEE7O0FBV0EsV0FBQSxLQUFBLEdBQUEsS0FBQTtBQUNBLFdBQUEsUUFBQSxHQUFBO0FBQ0EsY0FBQSxPQUFBLEtBQUEsQ0FBQSxDQUFBO0FBREEsS0FBQTs7QUFJQSxXQUFBLEVBQUEsR0FBQSxZQUFBO0FBQ0EsMEJBQUEsS0FBQSxDQUFBLE9BQUEsUUFBQSxDQUFBLElBQUE7QUFDQSxLQUZBOztBQUlBLFdBQUEsTUFBQSxHQUFBLFlBQUE7QUFDQSwwQkFBQSxPQUFBLENBQUEsUUFBQTtBQUNBLEtBRkE7QUFHQSxDQTdCQTtBQ2pDQSxJQUFBLFVBQUEsQ0FBQSxjQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUE7O0FBRUEsV0FBQSxpQkFBQSxHQUFBLElBQUE7O0FBRUEsV0FBQSxJQUFBLEdBQUEsVUFBQSxJQUFBLEVBQUE7O0FBRUEsWUFBQSxnQkFBQSxVQUFBLElBQUEsQ0FBQTtBQUNBLHVCQUFBLE9BQUEsaUJBREE7QUFFQSx5QkFBQSxzQkFGQTtBQUdBLHdCQUFBLHNCQUhBO0FBSUEsa0JBQUEsSUFKQTtBQUtBLHFCQUFBO0FBQ0EsdUJBQUEsaUJBQUE7QUFDQSwyQkFBQSxPQUFBLEtBQUE7QUFDQTtBQUhBO0FBTEEsU0FBQSxDQUFBOztBQVlBLHNCQUFBLE1BQUEsQ0FBQSxJQUFBLENBQUEsVUFBQSxZQUFBLEVBQUE7QUFDQSxtQkFBQSxRQUFBLEdBQUEsWUFBQTtBQUNBLFNBRkEsRUFFQSxZQUFBO0FBQ0EsaUJBQUEsSUFBQSxDQUFBLHlCQUFBLElBQUEsSUFBQSxFQUFBO0FBQ0EsU0FKQTtBQUtBLEtBbkJBO0FBcUJBLENBekJBOztBQTRCQSxJQUFBLFVBQUEsQ0FBQSxzQkFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLGlCQUFBLEVBQUEsS0FBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBOztBQUVBLFdBQUEsWUFBQSxHQUFBLGVBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsWUFBQTtBQUNBLHFCQUFBLFFBQUEsQ0FBQSxPQUFBLE1BQUE7O0FBRUEsS0FIQTs7QUFLQSxXQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsMEJBQUEsT0FBQSxDQUFBLFFBQUE7QUFDQSxLQUZBO0FBR0EsQ0FkQTtBQzVCQSxJQUFBLFVBQUEsQ0FBQSxlQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQSxTQUFBLEVBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsU0FBQTs7QUFHQSxhQUFBLGFBQUEsR0FBQTtBQUNBLGVBQUEsT0FBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLFFBQUEsT0FBQSxTQUFBLENBQUEsQ0FBQSxDQUFBOztBQUdBLGFBQUEsSUFBQSxJQUFBLElBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxPQUFBLENBQUEsSUFBQSxDQUFBLElBQUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7OztBQUlBLGFBQUEsVUFBQSxHQUFBO0FBQ0EsWUFBQSxLQUFBO0FBQ0EsZUFBQSxhQUFBLEdBQUEsRUFBQTtBQUNBLGtCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLFlBQUEsRUFBQTtBQUNBLGlCQUFBLElBQUEsSUFBQSxJQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBLFVBQUEsSUFBQSxDQUFBLElBQUEsSUFBQSxDQUFBO0FBQ0E7QUFDQSxtQkFBQSxhQUFBLENBQUEsSUFBQSxDQUFBLFNBQUE7QUFDQSxTQU5BO0FBT0E7OztBQUdBO0FBR0EsQ0FyQ0E7QUNBQSxJQUFBLFVBQUEsQ0FBQSxnQkFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUE7O0FBRUEsV0FBQSxPQUFBLEdBQUEsVUFBQSxlQUFBLEVBQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxDQUFBLGVBQUEsRUFBQSxPQUFBLElBQUEsQ0FBQSxLQUNBO0FBQ0EsaUJBQUEsSUFBQSxJQUFBLElBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsVUFBQSxJQUFBLElBQUEsRUFBQSxRQUFBLEdBQUEsV0FBQSxFQUFBO0FBQ0Esb0JBQUEsWUFBQSxnQkFBQSxRQUFBLEdBQUEsV0FBQSxFQUFBO0FBQ0Esd0JBQUEsR0FBQSxDQUFBLE9BQUEsRUFBQSxTQUFBLEVBQUEsUUFBQSxPQUFBLENBQUEsU0FBQSxNQUFBLENBQUEsQ0FBQTtBQUNBLG9CQUFBLFFBQUEsT0FBQSxDQUFBLFNBQUEsTUFBQSxDQUFBLENBQUEsRUFBQSxPQUFBLElBQUE7QUFDQTtBQUNBO0FBQ0EsZUFBQSxLQUFBO0FBQ0EsS0FYQTtBQWFBLENBZkE7QUNBQSxJQUFBLFVBQUEsQ0FBQSxpQkFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUEsV0FBQSxFQUFBLE9BQUEsRUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLFlBQUEsRUFBQSxJQUFBLEVBQUE7Ozs7QUFJQSxXQUFBLFNBQUEsR0FBQSxhQUFBLE1BQUE7QUFDQSxXQUFBLFlBQUEsR0FBQSxhQUFBLFNBQUE7QUFDQSxXQUFBLFdBQUEsR0FBQSxZQUFBLENBQUEsRUFBQSxJQUFBLENBQUEsVUFBQSxDQUFBLEVBQUEsQ0FBQSxFQUFBO0FBQ0EsWUFBQSxFQUFBLEVBQUEsR0FBQSxFQUFBLEVBQUEsRUFBQSxPQUFBLENBQUE7QUFDQSxZQUFBLEVBQUEsRUFBQSxHQUFBLEVBQUEsRUFBQSxFQUFBLE9BQUEsQ0FBQSxDQUFBO0FBQ0EsZUFBQSxDQUFBO0FBQ0EsS0FKQSxDQUFBO0FBS0EsV0FBQSxXQUFBLEdBQUEsS0FBQTtBQUNBLFdBQUEsWUFBQSxHQUFBLFlBQUE7O0FBR0EsYUFBQSxnQkFBQSxHQUFBO0FBQ0EsWUFBQSxjQUFBLEVBQUE7QUFDQSxlQUFBLFlBQUEsQ0FBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxJQUFBLE1BQUEsS0FBQSxPQUFBLFlBQUEsSUFBQSxJQUFBLGFBQUEsS0FBQSxRQUFBLEVBQUE7QUFDQSw0QkFBQSxJQUFBLE1BQUEsSUFBQSxJQUFBLE1BQUE7QUFDQSxhQUZBLE1BRUEsSUFBQSxJQUFBLE1BQUEsS0FBQSxPQUFBLFlBQUEsSUFBQSxJQUFBLGFBQUEsS0FBQSxRQUFBLEVBQUE7QUFDQSw0QkFBQSxJQUFBLE1BQUEsSUFBQSxJQUFBLE1BQUE7QUFDQTtBQUNBLFNBTkE7QUFPQSxlQUFBLFdBQUEsR0FBQSxXQUFBO0FBQ0E7O0FBRUE7O0FBR0EsV0FBQSxZQUFBLEdBQUEsWUFBQTs7QUFFQSxXQUFBLE9BQUEsR0FBQSxDQUFBOztBQUVBLFdBQUEsR0FBQSxHQUFBLE9BQUEsV0FBQSxDQUFBLEdBQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGVBQUEsSUFBQSxFQUFBO0FBQ0EsS0FGQSxDQUFBOzs7QUFLQSxXQUFBLFVBQUEsR0FBQSxLQUFBO0FBQ0EsV0FBQSxZQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsVUFBQSxHQUFBLENBQUEsT0FBQSxVQUFBO0FBQ0EsS0FGQTs7QUFJQSxXQUFBLGNBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsYUFBQSxFQUFBO0FBQ0EsYUFBQSxJQUFBLElBQUEsY0FBQSxNQUFBLEdBQUEsQ0FBQSxFQUFBLEtBQUEsQ0FBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLE1BQUEsY0FBQSxDQUFBLENBQUE7QUFDQSxnQkFBQSxTQUFBLENBQUE7QUFDQSxvQkFBQSxHQUFBLENBQUEsR0FBQTtBQUNBLGdCQUFBLElBQUEsUUFBQSxFQUFBO0FBQ0EsNkJBQUEsU0FBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsSUFBQSxRQUFBLEVBQUEsQ0FBQSxFQUFBLE9BQUEsQ0FBQSxFQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSwyQkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsaUJBSkE7QUFLQTtBQUNBO0FBQ0EsZUFBQSxVQUFBLEdBQUEsS0FBQTtBQUNBLEtBZEE7O0FBZ0JBLFdBQUEsU0FBQSxHQUFBLFVBQUEsYUFBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLFdBQUEsRUFBQTtBQUNBLDBCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFFBQUEsR0FBQSxJQUFBO0FBQ0EsYUFGQTtBQUdBLFNBSkEsTUFJQTtBQUNBLDBCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFFBQUEsR0FBQSxLQUFBO0FBQ0EsYUFGQTtBQUdBO0FBQ0EsS0FWQTs7QUFZQSxXQUFBLGdCQUFBLEdBQUEsVUFBQSxhQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsV0FBQSxLQUFBLElBQUEsRUFBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxLQUFBO0FBQ0E7QUFDQSxLQUpBOztBQU1BLFdBQUEsU0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxHQUFBLEVBQUEsYUFBQSxFQUFBO0FBQ0EsWUFBQSxTQUFBLGNBQUEsTUFBQSxHQUFBLENBQUE7QUFDQSxxQkFBQSxTQUFBLENBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxHQUFBLEVBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE1BQUEsRUFBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxNQUFBO0FBQ0E7QUFDQSxTQUpBO0FBS0EsS0FQQTs7QUFTQSxXQUFBLFlBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUFBO0FBQ0EscUJBQUEsWUFBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE1BQUEsRUFBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxNQUFBO0FBQ0E7QUFDQTtBQUNBLFNBTEE7QUFNQSxLQVBBOztBQVNBLFdBQUEsTUFBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLFNBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxDQUFBLFVBQUEsT0FBQSxFQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBLFFBQUEsTUFBQSxDQUFBLENBQUEsRUFBQSxLQUFBO0FBQ0EsU0FGQTtBQUdBLFlBQUEsU0FBQSxPQUFBLElBQUEsQ0FBQSxVQUFBLENBQUEsRUFBQSxDQUFBLEVBQUE7QUFDQSxtQkFBQSxJQUFBLENBQUE7QUFDQSxTQUZBLENBQUE7QUFHQSxZQUFBLE9BQUEsTUFBQSxHQUFBLENBQUEsRUFBQTtBQUNBLHlCQUFBLE1BQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsYUFKQTtBQU1BLFNBUEEsTUFPQTtBQUNBLHlCQUFBLE1BQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLENBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsYUFKQTtBQUtBO0FBQ0EsS0F0QkE7O0FBd0JBLFdBQUEsU0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQTtBQUNBLFlBQUEsVUFBQSxPQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsR0FBQSxFQUFBLEtBQUEsQ0FBQSxNQUFBLENBQUE7QUFDQSxZQUFBLE9BQUEsRUFBQTtBQUNBLGdCQUFBLGFBQUEsUUFBQSxJQUFBLENBQUEsVUFBQSxDQUFBLEVBQUEsQ0FBQSxFQUFBO0FBQ0EsdUJBQUEsSUFBQSxDQUFBO0FBQ0EsYUFGQSxDQUFBO0FBR0EsZ0JBQUEsV0FBQSxPQUFBLFdBQUEsQ0FBQSxDQUFBLElBQUEsQ0FBQTtBQUNBLGdCQUFBLGFBQUEsWUFBQSxTQUFBLFFBQUEsRUFBQTs7QUFFQSx5QkFBQSxTQUFBLENBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxVQUFBLEVBQ0EsSUFEQSxDQUNBLFlBQUE7QUFDQSx1QkFBQSxhQUFBLGNBQUEsQ0FBQSxhQUFBLE1BQUEsRUFBQSxhQUFBLFNBQUEsQ0FBQTtBQUNBLGFBSEEsRUFJQSxJQUpBLENBSUEsVUFBQSxRQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLEdBQUEsU0FBQSxDQUFBLENBQUE7QUFDQTtBQUNBO0FBQ0EsYUFSQTtBQVNBLFNBaEJBLE1BZ0JBO0FBQ0EsZ0JBQUEsYUFBQSxPQUFBLE9BQUEsQ0FBQSxNQUFBLEdBQUEsQ0FBQTtBQUNBLGdCQUFBLGFBQUEsWUFBQSxVQUFBO0FBQ0EseUJBQUEsU0FBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUNBLElBREEsQ0FDQSxZQUFBO0FBQ0EsdUJBQUEsYUFBQSxjQUFBLENBQUEsYUFBQSxNQUFBLEVBQUEsYUFBQSxTQUFBLENBQUE7QUFDQSxhQUhBLEVBSUEsSUFKQSxDQUlBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsdUJBQUEsV0FBQSxHQUFBLFNBQUEsQ0FB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QUZBOztBQUlBLFdBQUEsV0FBQSxHQUFBLGFBQUEsV0FBQTs7Ozs7Ozs7QUFTQSxXQUFBLGVBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsYUFBQSxHQUFBLFVBQUEsR0FBQSxFQUFBLFVBQUEsRUFBQSxDQUFBLEVBQUE7QUFDQSxlQUFBLE9BQUEsQ0FBQSxDQUFBLElBQUEsVUFBQTs7QUFFQSxZQUFBLFNBQUEsRUFBQSxRQUFBLE9BQUEsZUFBQSxDQUFBLENBQUEsQ0FBQSxFQUFBLFFBQUEsVUFBQSxFQUFBOzs7QUFHQSxZQUFBLE9BQUEsZUFBQSxDQUFBLE1BQUEsS0FBQSxDQUFBLEVBQUE7QUFBQSxtQkFBQSxlQUFBLENBQUEsSUFBQSxDQUFBLE1BQUE7QUFBQSxTQUFBLE1BQUE7QUFDQSxpQkFBQSxJQUFBLElBQUEsQ0FBQSxFQUFBLElBQUEsT0FBQSxlQUFBLENBQUEsTUFBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLE9BQUEsZUFBQSxDQUFBLENBQUEsRUFBQSxNQUFBLEtBQUEsT0FBQSxNQUFBLEVBQUE7QUFDQSwyQkFBQSxlQUFBLENBQUEsQ0FBQSxJQUFBLE1BQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQSxtQkFBQSxlQUFBLENBQUEsSUFBQSxDQUFBLE1BQUE7QUFDQTs7QUFFQSxLQWhCQTs7OztBQW9CQSxXQUFBLGVBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLFVBQUEsR0FBQSxFQUFBLE9BQUEsRUFBQSxHQUFBLEVBQUEsQ0FBQSxFQUFBLENBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxPQUFBLGVBQUE7QUFDQSxZQUFBLFFBQUEsS0FBQTtBQUNBLFlBQUEsVUFBQSxLQUFBLENBQUEsQ0FBQTtBQUNBLGFBQUEsSUFBQSxJQUFBLENBQUEsRUFBQSxJQUFBLE9BQUEsZUFBQSxDQUFBLE1BQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxNQUFBLE9BQUEsZUFBQSxDQUFBLENBQUEsQ0FBQTtBQUNBLG9CQUFBLEdBQUEsQ0FBQSxHQUFBO0FBQ0EsZ0JBQUEsSUFBQSxJQUFBLE1BQUEsQ0FBQSxFQUFBO0FBQ0Esd0JBQUEsSUFBQTtBQUNBLG9CQUFBLElBQUEsT0FBQSxDQUFBLEVBQUEsSUFBQSxPQUFBLElBQUEsT0FBQTtBQUNBLG9CQUFBLE9BQUEsSUFBQSxPQUFBO0FBQ0E7QUFDQTtBQUNBLFlBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSxnQkFBQSxTQUFBLEVBQUE7QUFDQSxtQkFBQSxJQUFBLElBQUEsQ0FBQTtBQUNBLG1CQUFBLE9BQUEsSUFBQSxPQUFBO0FBQ0EsbUJBQUEsZUFBQSxDQUFBLElBQUEsQ0FBQSxNQUFBO0FBQ0E7QUFDQSxLQW5CQTs7QUFxQkEsV0FBQSxhQUFBLEdBQUEsWUFBQTtBQUNBLFlBQUEsT0FBQSxFQUFBLE1BQUEsT0FBQSxlQUFBLEVBQUEsU0FBQSxPQUFBLGVBQUEsRUFBQTtBQUNBLHFCQUFBLGFBQUEsQ0FBQSxPQUFBLFNBQUEsRUFBQSxPQUFBLFlBQUEsRUFBQSxJQUFBO0FBQ0EsS0FIQTs7QUFNQSxXQUFBLFdBQUEsR0FBQSxZQUFBO0FBQ0EscUJBQUEsV0FBQSxDQUFBLE9BQUEsWUFBQSxFQUNBLElBREEsQ0FDQSxZQUFBO0FBQ0EsbUJBQUEsRUFBQSxDQUFBLE9BQUEsRUFBQSxFQUFBLFFBQUEsT0FBQSxTQUFBLEVBQUEsRUFBQSxFQUFBLFFBQUEsSUFBQSxFQUFBO0FBQ0EsU0FIQTtBQUlBLEtBTEE7Ozs7QUFTQSxXQUFBLHdCQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLGFBQUEsR0FBQSxFQUFBOztBQUVBLGlCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsSUFBQSxNQUFBLEtBQUEsT0FBQSxZQUFBLElBQUEsT0FBQSx3QkFBQSxDQUFBLE9BQUEsQ0FBQSxJQUFBLE1BQUEsS0FBQSxDQUFBLENBQUEsRUFBQTtBQUNBLG1CQUFBLHdCQUFBLENBQUEsSUFBQSxDQUFBLElBQUEsTUFBQTtBQUNBLFNBRkEsTUFFQSxJQUFBLElBQUEsTUFBQSxLQUFBLE9BQUEsWUFBQSxJQUFBLE9BQUEsd0JBQUEsQ0FBQSxPQUFBLENBQUEsSUFBQSxNQUFBLEtBQUEsQ0FBQSxDQUFBLEVBQUE7QUFDQSxtQkFBQSx3QkFBQSxDQUFBLElBQUEsQ0FBQSxJQUFBLE1BQUE7QUFDQTtBQUNBLEtBTkE7O0FBUUEsV0FBQSxhQUFBLEdBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsYUFBQSxDQUFBLE9BQUEsQ0FBQSxPQUFBLHdCQUFBLENBQUEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBLEVBQUE7QUFDQSxtQkFBQSxhQUFBLENBQUEsSUFBQSxDQUFBLE9BQUEsd0JBQUEsQ0FBQSxHQUFBLENBQUE7QUFDQSxTQUZBLE1BRUE7QUFDQSxnQkFBQSxJQUFBLE9BQUEsYUFBQSxDQUFBLE9BQUEsQ0FBQSxPQUFBLHdCQUFBLENBQUEsR0FBQSxDQUFBLENBQUE7QUFDQSxtQkFBQSxhQUFBLENBQUEsTUFBQSxDQUFBLENBQUEsRUFBQSxDQUFBO0FBQ0E7QUFDQSxLQVBBOztBQVNBLFdBQUEsZUFBQSxHQUFBLEVBQUE7O0FBRUEsV0FBQSxrQkFBQSxHQUFBLFlBQUE7QUFDQSxZQUFBLHFCQUFBLEVBQUE7QUFDQSxlQUFBLGFBQUEsQ0FBQSxPQUFBLENBQUEsVUFBQSxTQUFBLEVBQUE7QUFDQSxtQkFBQSxtQkFBQSxJQUFBLENBQUEsYUFBQSxrQkFBQSxDQUFBLE9BQUEsU0FBQSxFQUFBLFNBQUEsQ0FBQSxDQUFBO0FBQ0EsU0FGQTtBQUdBLGdCQUFBLEdBQUEsQ0FBQSxrQkFBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE9BQUEsRUFBQTtBQUNBLG9CQUFBLE9BQUEsQ0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLHVCQUFBLGVBQUEsQ0FBQSxJQUFBLENBQUEsTUFBQTtBQUNBLHVCQUFBLFVBQUE7QUFDQSxhQUhBO0FBSUEsU0FOQTtBQVFBLEtBYkE7O0FBZUEsUUFBQSxrQkFBQSxFQUFBO0FBQ0EsUUFBQSxVQUFBOztBQUVBLFdBQUEsa0JBQUEsR0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsQ0FBQSxlQUFBLEVBQUEsa0JBQUEsRUFBQTs7QUFFQSxZQUFBLGFBQUEsT0FBQSxlQUFBLENBQUEsQ0FBQSxFQUFBLFNBQUEsRUFBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLFlBQUEsWUFBQSxJQUFBLFNBQUE7QUFDQSxxQkFBQSxTQUFBOztBQUVBLFlBQUEsQ0FBQSxnQkFBQSxTQUFBLENBQUEsRUFBQSxnQkFBQSxTQUFBLElBQUEsRUFBQTtBQUNBLFlBQUEsZ0JBQUEsU0FBQSxFQUFBLE9BQUEsQ0FBQSxVQUFBLE1BQUEsQ0FBQSxDQUFBLEVBQUE7QUFDQSw0QkFBQSxTQUFBLEVBQUEsTUFBQSxDQUFBLGdCQUFBLFNBQUEsRUFBQSxPQUFBLENBQUEsVUFBQSxDQUFBLEVBQUEsQ0FBQTtBQUNBLFNBRkEsTUFFQTtBQUNBLDRCQUFBLFNBQUEsRUFBQSxJQUFBLENBQUEsVUFBQTtBQUNBO0FBQ0EsZUFBQSxlQUFBLEdBQUEsZUFBQTtBQUNBLEtBZEE7OztBQWtCQSxXQUFBLGFBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsV0FBQTs7QUFFQSxXQUFBLEdBQUEsR0FBQSxFQUFBOzs7O0FBS0EsV0FBQSxPQUFBLEdBQUEsWUFBQTs7QUFFQSxZQUFBLGtCQUFBLE9BQUEsT0FBQSxDQUFBLEdBQUEsQ0FBQSxVQUFBLE9BQUEsRUFBQTtBQUNBLG1CQUFBLE9BQUEsWUFBQSxHQUFBLEdBQUEsR0FBQSxPQUFBO0FBQ0EsU0FGQSxDQUFBO0FBR0EsYUFBQSxJQUFBLElBQUEsSUFBQSxPQUFBLGVBQUEsRUFBQTtBQUNBLG1CQUFBLGVBQUEsQ0FBQSxJQUFBLEVBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0NBQUEsSUFBQSxDQUFBLE9BQUEsR0FBQSxHQUFBLEdBQUE7QUFDQSxhQUZBO0FBR0E7QUFDQSxxQkFBQSxPQUFBLENBQUEsT0FBQSxTQUFBLEVBQUEsT0FBQSxZQUFBLEVBQUEsT0FBQSxhQUFBLEVBQUEsT0FBQSxlQUFBLEVBQUEsT0FBQSxZQUFBLEVBQUEsZUFBQSxFQUNBLElBREEsQ0FDQSxVQUFBLFdBQUEsRUFBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxXQUFBO0FBQ0EsU0FIQSxFQUlBLElBSkEsQ0FJQSxZQUFBO0FBQ0EsbUJBQUEsRUFBQSxDQUFBLG9CQUFBO0FBQ0EsU0FOQTtBQU9BLEtBakJBOztBQW1CQSxXQUFBLGlCQUFBLEdBQUEsSUFBQTs7QUFFQSxXQUFBLElBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxPQUFBLEVBQUEsR0FBQSxFQUFBLEtBQUEsRUFBQTs7QUFFQSxZQUFBLGdCQUFBLFVBQUEsSUFBQSxDQUFBO0FBQ0EsdUJBQUEsT0FBQSxpQkFEQTtBQUVBLHNCQUFBLEtBRkE7QUFHQSx5QkFBQSxpQ0FIQTtBQUlBLHdCQUFBLHlCQUpBO0FBS0EscUJBQUE7QUFDQSw2QkFBQSx1QkFBQTtBQUNBLDJCQUFBLE9BQUEsV0FBQTtBQUNBLGlCQUhBO0FBSUEsMEJBQUEsa0JBQUEsWUFBQSxFQUFBO0FBQ0EsNEJBQUEsR0FBQSxDQUFBLE9BQUE7QUFDQSwyQkFBQSxhQUFBLFdBQUEsQ0FBQSxNQUFBLEVBQUEsT0FBQSxDQUFBO0FBQ0EsaUJBUEE7QUFRQSw4QkFBQSx3QkFBQTtBQUNBLDJCQUFBLE9BQUE7QUFDQSxpQkFWQTtBQVdBLDJCQUFBLHFCQUFBO0FBQ0EsMkJBQUEsT0FBQSxZQUFBO0FBQ0EsaUJBYkE7QUFjQSx5QkFBQSxtQkFBQTtBQUNBLDJCQUFBLEdBQUE7QUFDQSxpQkFoQkE7QUFpQkEscUJBQUEsZUFBQTtBQUNBLDJCQUFBLEtBQUE7QUFDQTtBQW5CQTtBQUxBLFNBQUEsQ0FBQTs7QUE0QkEsc0JBQUEsTUFBQSxDQUFBLElBQUEsQ0FBQSxZQUFBO0FBQ0Esb0JBQUEsR0FBQSxDQUFBLFFBQUE7QUFDQSxtQkFBQSxVQUFBO0FBQ0EsU0FIQTtBQUlBLEtBbENBOztBQW9DQSxXQUFBLGVBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxpQkFBQSxHQUFBLENBQUEsT0FBQSxpQkFBQTtBQUNBLEtBRkE7O0FBSUEsV0FBQSxZQUFBLEdBQUEsRUFBQTtBQUNBLFdBQUEsV0FBQSxHQUFBLENBQUE7QUFDQSxXQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsV0FBQSxPQUFBLEdBQUEsQ0FBQTs7QUFFQSxXQUFBLE1BQUEsQ0FBQSwwQkFBQSxFQUFBLFlBQUE7QUFDQSxZQUFBLFFBQUEsQ0FBQSxPQUFBLFdBQUEsR0FBQSxDQUFBLElBQUEsT0FBQSxVQUFBO0FBQ0EsWUFBQSxNQUFBLFFBQUEsT0FBQSxVQUFBO0FBQ0EsZUFBQSxZQUFBLEdBQUEsT0FBQSxhQUFBLENBQUEsS0FBQSxDQUFBLEtBQUEsRUFBQSxHQUFBLENBQUE7QUFDQSxLQUpBO0FBTUEsQ0FsY0E7O0FDQUEsSUFBQSxVQUFBLENBQUEsV0FBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxNQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQSxTQUFBLEVBQUEsV0FBQSxFQUFBLFlBQUEsRUFBQSxVQUFBLEVBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsU0FBQTs7QUFFQSxXQUFBLFdBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsTUFBQSxHQUFBLGFBQUEsTUFBQTs7QUFFQSxXQUFBLFlBQUEsR0FBQSxZQUFBOztBQUVBLFdBQUEsVUFBQSxHQUFBLFVBQUE7O0FBRUEsV0FBQSxnQkFBQSxHQUFBLGFBQUEsTUFBQSxHQUFBLFFBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsT0FBQSxTQUFBLENBQUEsSUFBQSxDQUFBLE1BQUE7O0FBRUEsV0FBQSxHQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsV0FBQSxDQUFBLElBQUEsQ0FBQSxHQUFBO0FBQ0EsS0FGQTs7QUFJQSxXQUFBLE1BQUEsR0FBQSxNQUFBLEM7O0FBRUEsV0FBQSxnQkFBQSxHQUFBLENBQUEsUUFBQSxFQUFBLFNBQUEsQ0FBQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxhQUFBLE1BQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsS0FBQTs7QUFFQSxXQUFBLGdCQUFBLEdBQUEsVUFBQSxXQUFBLEVBQUEsTUFBQSxFQUFBO0FBQ0EsZUFBQSxTQUFBLEdBQUEsSUFBQTtBQUNBLHFCQUFBLGdCQUFBLENBQUEsV0FBQSxFQUFBLE1BQUE7Ozs7QUFJQSxLQU5BOztBQVFBLFdBQUEsWUFBQSxHQUFBLFVBQUEsU0FBQSxFQUFBO0FBQ0EsWUFBQSxjQUFBLGVBQUEsSUFBQSxjQUFBLG1CQUFBLEVBQUEsT0FBQSxJQUFBO0FBQ0EsS0FGQTs7QUFJQSxXQUFBLFdBQUEsR0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLHFCQUFBLFdBQUEsQ0FBQSxLQUFBLEVBQ0EsSUFEQSxDQUNBLFlBQUE7QUFDQSxtQkFBQSxFQUFBLENBQUEsT0FBQSxFQUFBLEVBQUEsUUFBQSxPQUFBLE1BQUEsRUFBQSxFQUFBLEVBQUEsUUFBQSxJQUFBLEVBQUE7QUFDQSxTQUhBO0FBSUEsS0FMQTs7QUFPQSxXQUFBLGNBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxVQUFBLENBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxVQUFBLEtBQUEsT0FBQSxLQUFBLENBQUEsTUFBQSxJQUFBLElBQUEsV0FBQSxLQUFBLE9BQUEsS0FBQSxDQUFBLE1BQUEsRUFBQSxPQUFBLElBQUEsR0FBQSxJQUFBLFNBQUE7QUFDQSxTQUZBO0FBR0EsS0FKQTs7QUFNQSxXQUFBLGFBQUEsR0FBQSxFQUFBOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUEyQkEsV0FBQSxXQUFBLEdBQUEsYUFBQSxXQUFBO0FBRUEsQ0FsRkE7O0FDQUEsSUFBQSxPQUFBLENBQUEsY0FBQSxFQUFBLFVBQUEsS0FBQSxFQUFBLFlBQUEsRUFBQTs7QUFFQSxRQUFBLGVBQUEsRUFBQTs7QUFFQSxhQUFBLFNBQUEsQ0FBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLElBQUEsSUFBQTtBQUNBOztBQUVBLGlCQUFBLFlBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUJBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGNBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFNBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUJBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLE1BQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsSUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsR0FBQSxTQUFBLEVBQUEsSUFBQSxDQUFBO0FBQ0EsS0FGQTs7QUFJQSxpQkFBQSxhQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLElBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsa0JBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQUEsSUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLE1BQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLElBQUEsQ0FBQSx5QkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsRUFBQSxFQUFBLFdBQUEsU0FBQSxFQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsU0FBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxLQUFBLEVBQUEsTUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLE1BQUEsQ0FBQSxtQkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsR0FBQSxHQUFBLEdBQUEsS0FBQSxHQUFBLEdBQUEsR0FBQSxNQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsWUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxVQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsTUFBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxHQUFBLFVBQUEsR0FBQSxVQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsU0FBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxDQUFBLDRCQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLENBQUE7QUFDQSxLQUZBO0FBR0EsaUJBQUEsV0FBQSxHQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0EsY0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBO0FBQ0EsZUFBQSxNQUFBLElBQUEsQ0FBQSxlQUFBLEVBQUEsS0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUpBOztBQU1BLGlCQUFBLFdBQUEsR0FBQSxVQUFBLFlBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsYUFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLGFBQUEsU0FBQSxDQUFBO0FBQ0EsS0FGQTs7QUFJQSxpQkFBQSxnQkFBQSxHQUFBLFVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxJQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLGNBQUEsRUFBQSxXQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsUUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLE1BQUEsQ0FBQSxtQkFBQSxNQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsZUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsb0NBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsa0JBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUNBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsaUNBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGtCQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQ0FBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxPQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBLGFBQUEsRUFBQSxlQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxFQUFBO0FBQ0EsYUFBQSxNQUFBLEdBQUEsTUFBQTtBQUNBLGFBQUEsTUFBQSxHQUFBLGNBQUEsQ0FBQSxDQUFBO0FBQ0EsYUFBQSxhQUFBLEdBQUEsYUFBQTtBQUNBLGFBQUEsZUFBQSxHQUFBLGVBQUE7QUFDQSxhQUFBLFlBQUEsR0FBQSxZQUFBOzs7O0FBSUEscUJBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxNQUFBLEtBQUEsTUFBQSxJQUFBLElBQUEsTUFBQSxLQUFBLEtBQUEsTUFBQSxFQUFBO0FBQ0EscUJBQUEsS0FBQSxHQUFBLElBQUEsTUFBQTtBQUNBLG9CQUFBLElBQUEsYUFBQSxLQUFBLFFBQUEsRUFBQTtBQUNBLHlCQUFBLE1BQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EsaUJBSEEsTUFJQTtBQUNBLHlCQUFBLE1BQUEsR0FBQSxJQUFB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LEVBQUE7QUFDQSxhQUZBOztBQUlBLGtCQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsNEJBQUEsTUFBQSxHQUFBLElBQUEsQ0FBQSxZQUFBO0FBQ0EsMkJBQUEsRUFBQSxDQUFBLGFBQUE7QUFDQSxpQkFGQTtBQUdBLGFBSkE7O0FBTUEsZ0JBQUEsVUFBQSxTQUFBLE9BQUEsR0FBQTtBQUNBLDRCQUFBLGVBQUEsR0FBQSxJQUFBLENBQUEsVUFBQSxJQUFBLEVBQUE7QUFDQSwwQkFBQSxJQUFBLEdBQUEsSUFBQTtBQUNBLGlCQUZBO0FBR0EsYUFKQTs7QUFNQSxnQkFBQSxhQUFBLFNBQUEsVUFBQSxHQUFBO0FBQ0Esc0JBQUEsSUFBQSxHQUFBLElBQUE7QUFDQSxhQUZBOztBQUlBOztBQUVBLHVCQUFBLEdBQUEsQ0FBQSxZQUFBLFlBQUEsRUFBQSxPQUFBO0FBQ0EsdUJBQUEsR0FBQSxDQUFBLFlBQUEsYUFBQSxFQUFBLFVBQUE7QUFDQSx1QkFBQSxHQUFBLENBQUEsWUFBQSxjQUFBLEVBQUEsVUFBQTtBQUVBOztBQXpDQSxLQUFBO0FBNkNBLENBL0NBOztBQ0FBLElBQUEsU0FBQSxDQUFBLGVBQUEsRUFBQSxVQUFBLGVBQUEsRUFBQTs7QUFFQSxXQUFBO0FBQ0Esa0JBQUEsR0FEQTtBQUVBLHFCQUFBLHlEQUZBO0FBR0EsY0FBQSxjQUFBLEtBQUEsRUFBQTtBQUNBLGtCQUFBLFFBQUEsR0FBQSxnQkFBQSxpQkFBQSxFQUFBO0FBQ0E7QUFMQSxLQUFBO0FBUUEsQ0FWQSIsImZpbGUiOiJtYWluLmpzIiwic291cmNlc0NvbnRlbnQiOlsiJ3VzZSBzdHJpY3QnO1xud2luZG93LmFwcCA9IGFuZ3VsYXIubW9kdWxlKCdGdWxsc3RhY2tHZW5lcmF0ZWRBcHAnLCBbJ2ZzYVByZUJ1aWx0JywgJ3VpLnJvdXRlcicsICd1aS5ib290c3RyYXAnLCAnbmdBbmltYXRlJ10pO1xuXG5hcHAuY29uZmlnKGZ1bmN0aW9uICgkdXJsUm91dGVyUHJvdmlkZXIsICRsb2NhdGlvblByb3ZpZGVyKSB7XG4gICAgLy8gVGhpcyB0dXJucyBvZmYgaGFzaGJhbmcgdXJscyAoLyNhYm91dCkgYW5kIGNoYW5nZXMgaXQgdG8gc29tZXRoaW5nIG5vcm1hbCAoL2Fib3V0KVxuICAgICRsb2NhdGlvblByb3ZpZGVyLmh0bWw1TW9kZSh0cnVlKTtcbiAgICAvLyBJZiB3ZSBnbyB0byBhIFVSTCB0aGF0IHVpLXJvdXRlciBkb2Vzbid0IGhhdmUgcmVnaXN0ZXJlZCwgZ28gdG8gdGhlIFwiL1wiIHVybC5cbiAgICAkdXJsUm91dGVyUHJvdmlkZXIub3RoZXJ3aXNlKCcvJyk7XG4gICAgLy8gVHJpZ2dlciBwYWdlIHJlZnJlc2ggd2hlbiBhY2Nlc3NpbmcgYW4gT0F1dGggcm91dGVcbiAgICAkdXJsUm91dGVyUHJvdmlkZXIud2hlbignL2F1dGgvOnByb3ZpZGVyJywgZnVuY3Rpb24gKCkge1xuICAgICAgICB3aW5kb3cubG9jYXRpb24ucmVsb2FkKCk7XG4gICAgfSk7XG59KTtcblxuLy8gVGhpcyBhcHAucnVuIGlzIGZvciBjb250cm9sbGluZyBhY2Nlc3MgdG8gc3BlY2lmaWMgc3RhdGVzLlxuYXBwLnJ1bihmdW5jdGlvbiAoJHJvb3RTY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICAgLy8gVGhlIGdpdmVuIHN0YXRlIHJlcXVpcmVzIGFuIGF1dGhlbnRpY2F0ZWQgdXNlci5cbiAgICB2YXIgZGVzdGluYXRpb25TdGF0ZVJlcXVpcmVzQXV0aCA9IGZ1bmN0aW9uIChzdGF0ZSkge1xuICAgICAgICByZXR1cm4gc3RhdGUuZGF0YSAmJiBzdGF0ZS5kYXRhLmF1dGhlbnRpY2F0ZTtcbiAgICB9O1xuXG4gICAgLy8gJHN0YXRlQ2hhbmdlU3RhcnQgaXMgYW4gZXZlbnQgZmlyZWRcbiAgICAvLyB3aGVuZXZlciB0aGUgcHJvY2VzcyBvZiBjaGFuZ2luZyBhIHN0YXRlIGJlZ2lucy5cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbiAoZXZlbnQsIHRvU3RhdGUsIHRvUGFyYW1zKSB7XG5cbiAgICAgICAgaWYgKCFkZXN0aW5hdGlvblN0YXRlUmVxdWlyZXNBdXRoKHRvU3RhdGUpKSB7XG4gICAgICAgICAgICAvLyBUaGUgZGVzdGluYXRpb24gc3RhdGUgZG9lcyBub3QgcmVxdWlyZSBhdXRoZW50aWNhdGlvblxuICAgICAgICAgICAgLy8gU2hvcnQgY2lyY3VpdCB3aXRoIHJldHVybi5cbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChBdXRoU2VydmljZS5pc0F1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAgICAgLy8gVGhlIHVzZXIgaXMgYXV0aGVudGljYXRlZC5cbiAgICAgICAgICAgIC8vIFNob3J0IGNpcmN1aXQgd2l0aCByZXR1cm4uXG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDYW5jZWwgbmF2aWdhdGluZyB0byBuZXcgc3RhdGUuXG4gICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG5cbiAgICAgICAgQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCkudGhlbihmdW5jdGlvbiAodXNlcikge1xuICAgICAgICAgICAgLy8gSWYgYSB1c2VyIGlzIHJldHJpZXZlZCwgdGhlbiByZW5hdmlnYXRlIHRvIHRoZSBkZXN0aW5hdGlvblxuICAgICAgICAgICAgLy8gKHRoZSBzZWNvbmQgdGltZSwgQXV0aFNlcnZpY2UuaXNBdXRoZW50aWNhdGVkKCkgd2lsbCB3b3JrKVxuICAgICAgICAgICAgLy8gb3RoZXJ3aXNlLCBpZiBubyB1c2VyIGlzIGxvZ2dlZCBpbiwgZ28gdG8gXCJsb2dpblwiIHN0YXRlLlxuICAgICAgICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgICAgICAgICAkc3RhdGUuZ28odG9TdGF0ZS5uYW1lLCB0b1BhcmFtcyk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnbG9naW4nKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG5cbiAgICB9KTtcblxufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuXG4gICAgLy8gUmVnaXN0ZXIgb3VyICphYm91dCogc3RhdGUuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2Fib3V0Jywge1xuICAgICAgICB1cmw6ICcvYWJvdXQnLFxuICAgICAgICBjb250cm9sbGVyOiAnQWJvdXRDb250cm9sbGVyJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9hYm91dC9hYm91dC5odG1sJ1xuICAgIH0pO1xuXG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ0Fib3V0Q29udHJvbGxlcicsIGZ1bmN0aW9uICgkc2NvcGUsIEZ1bGxzdGFja1BpY3MpIHtcblxuICAgIC8vIEltYWdlcyBvZiBiZWF1dGlmdWwgRnVsbHN0YWNrIHBlb3BsZS5cbiAgICAkc2NvcGUuaW1hZ2VzID0gXy5zaHVmZmxlKEZ1bGxzdGFja1BpY3MpO1xuXG59KTsiLCJhcHAuY29udHJvbGxlcignQ3JlYXRlZGJDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHN0YXRlLCBDcmVhdGVkYkZhY3RvcnkpIHtcblxuXHQkc2NvcGUuY3JlYXRlZERCID0gZmFsc2U7XG4gICAgICAgICRzY29wZS5jb2x1bW5BcnJheSA9IFtdO1xuXG5cdCRzY29wZS5hZGQgPSBmdW5jdGlvbigpIHtcblx0XHQkc2NvcGUuY29sdW1uQXJyYXkucHVzaCgnMScpO1xuXHR9XG5cblx0JHNjb3BlLmNyZWF0ZURCID0gZnVuY3Rpb24obmFtZSkge1xuXHRcdENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVEQihuYW1lKVxuXHRcdC50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcblx0XHRcdCRzY29wZS5jcmVhdGVkREIgPSBkYXRhO1xuXHRcdH0pXG5cdH1cblxuXHQkc2NvcGUuY3JlYXRlVGFibGUgPSBmdW5jdGlvbih0YWJsZSwgREIpe1xuXHRcdENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVUYWJsZSh0YWJsZSwgREIpXG5cdFx0XHQkc3RhdGUuZ28oJ1RhYmxlJywge2RiTmFtZTogJHNjb3BlLmNyZWF0ZWREQi5kYk5hbWV9LCB7cmVsb2FkOnRydWV9KVxuXHR9XG59KTtcbiIsImFwcC5mYWN0b3J5KCdDcmVhdGVkYkZhY3RvcnknLCBmdW5jdGlvbiAoJGh0dHApIHtcblxuXHR2YXIgQ3JlYXRlZGJGYWN0b3J5ID0ge307XG5cblx0ZnVuY3Rpb24gcmVzVG9EYXRhKHJlcykge1xuICAgICAgICByZXR1cm4gcmVzLmRhdGE7XG4gICAgfVxuXG4gICAgQ3JlYXRlZGJGYWN0b3J5LmNyZWF0ZURCID0gZnVuY3Rpb24oZGJOYW1lKSB7XG4gICAgXHRyZXR1cm4gJGh0dHAucG9zdCgnL2FwaS9tYXN0ZXJkYicsIGRiTmFtZSlcbiAgICBcdC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgIENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVUYWJsZSA9IGZ1bmN0aW9uKHRhYmxlLCBjcmVhdGVkREIpIHtcbiAgICB0YWJsZS5kYk5hbWUgPSBjcmVhdGVkREIuZGJOYW1lO1xuICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL2NsaWVudGRiJywgdGFibGUpXG4gICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgIH1cblxuXHRyZXR1cm4gQ3JlYXRlZGJGYWN0b3J5OyBcbn0pXG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdjcmVhdGVkYicsIHtcbiAgICAgICAgdXJsOiAnL2NyZWF0ZWRiJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jcmVhdGVkYi9jcmVhdGVkYi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0NyZWF0ZWRiQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgXHRsb2dnZWRJblVzZXI6IGZ1bmN0aW9uKEF1dGhTZXJ2aWNlKSB7XG4gICAgICAgIFx0XHRyZXR1cm4gQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCk7XG4gICAgICAgIFx0fVxuICAgICAgICB9XG4gICAgfSk7XG5cbn0pOyIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2RvY3MnLCB7XG4gICAgICAgIHVybDogJy9kb2NzJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9kb2NzL2RvY3MuaHRtbCdcbiAgICB9KTtcbn0pO1xuIiwiKGZ1bmN0aW9uICgpIHtcblxuICAgICd1c2Ugc3RyaWN0JztcblxuICAgIC8vIEhvcGUgeW91IGRpZG4ndCBmb3JnZXQgQW5ndWxhciEgRHVoLWRveS5cbiAgICBpZiAoIXdpbmRvdy5hbmd1bGFyKSB0aHJvdyBuZXcgRXJyb3IoJ0kgY2FuXFwndCBmaW5kIEFuZ3VsYXIhJyk7XG5cbiAgICB2YXIgYXBwID0gYW5ndWxhci5tb2R1bGUoJ2ZzYVByZUJ1aWx0JywgW10pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ1NvY2tldCcsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKCF3aW5kb3cuaW8pIHRocm93IG5ldyBFcnJvcignc29ja2V0LmlvIG5vdCBmb3VuZCEnKTtcbiAgICAgICAgcmV0dXJuIHdpbmRvdy5pbyh3aW5kb3cubG9jYXRpb24ub3JpZ2luKTtcbiAgICB9KTtcblxuICAgIC8vIEFVVEhfRVZFTlRTIGlzIHVzZWQgdGhyb3VnaG91dCBvdXIgYXBwIHRvXG4gICAgLy8gYnJvYWRjYXN0IGFuZCBsaXN0ZW4gZnJvbSBhbmQgdG8gdGhlICRyb290U2NvcGVcbiAgICAvLyBmb3IgaW1wb3J0YW50IGV2ZW50cyBhYm91dCBhdXRoZW50aWNhdGlvbiBmbG93LlxuICAgIGFwcC5jb25zdGFudCgnQVVUSF9FVkVOVFMnLCB7XG4gICAgICAgIGxvZ2luU3VjY2VzczogJ2F1dGgtbG9naW4tc3VjY2VzcycsXG4gICAgICAgIGxvZ2luRmFpbGVkOiAnYXV0aC1sb2dpbi1mYWlsZWQnLFxuICAgICAgICBsb2dvdXRTdWNjZXNzOiAnYXV0aC1sb2dvdXQtc3VjY2VzcycsXG4gICAgICAgIHNlc3Npb25UaW1lb3V0OiAnYXV0aC1zZXNzaW9uLXRpbWVvdXQnLFxuICAgICAgICBub3RBdXRoZW50aWNhdGVkOiAnYXV0aC1ub3QtYXV0aGVudGljYXRlZCcsXG4gICAgICAgIG5vdEF1dGhvcml6ZWQ6ICdhdXRoLW5vdC1hdXRob3JpemVkJ1xuICAgIH0pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ0F1dGhJbnRlcmNlcHRvcicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCAkcSwgQVVUSF9FVkVOVFMpIHtcbiAgICAgICAgdmFyIHN0YXR1c0RpY3QgPSB7XG4gICAgICAgICAgICA0MDE6IEFVVEhfRVZFTlRTLm5vdEF1dGhlbnRpY2F0ZWQsXG4gICAgICAgICAgICA0MDM6IEFVVEhfRVZFTlRTLm5vdEF1dGhvcml6ZWQsXG4gICAgICAgICAgICA0MTk6IEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LFxuICAgICAgICAgICAgNDQwOiBBVVRIX0VWRU5UUy5zZXNzaW9uVGltZW91dFxuICAgICAgICB9O1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KHN0YXR1c0RpY3RbcmVzcG9uc2Uuc3RhdHVzXSwgcmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVzcG9uc2UpXG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgfSk7XG5cbiAgICBhcHAuY29uZmlnKGZ1bmN0aW9uICgkaHR0cFByb3ZpZGVyKSB7XG4gICAgICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goW1xuICAgICAgICAgICAgJyRpbmplY3RvcicsXG4gICAgICAgICAgICBmdW5jdGlvbiAoJGluamVjdG9yKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRpbmplY3Rvci5nZXQoJ0F1dGhJbnRlcmNlcHRvcicpO1xuICAgICAgICAgICAgfVxuICAgICAgICBdKTtcbiAgICB9KTtcblxuICAgIGFwcC5zZXJ2aWNlKCdBdXRoU2VydmljZScsIGZ1bmN0aW9uICgkaHR0cCwgU2Vzc2lvbiwgJHJvb3RTY29wZSwgQVVUSF9FVkVOVFMsICRxKSB7XG5cbiAgICAgICAgZnVuY3Rpb24gb25TdWNjZXNzZnVsTG9naW4ocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHZhciBkYXRhID0gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgICAgIFNlc3Npb24uY3JlYXRlKGRhdGEuaWQsIGRhdGEudXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3QoQVVUSF9FVkVOVFMubG9naW5TdWNjZXNzKTtcbiAgICAgICAgICAgIHJldHVybiBkYXRhLnVzZXI7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBVc2VzIHRoZSBzZXNzaW9uIGZhY3RvcnkgdG8gc2VlIGlmIGFuXG4gICAgICAgIC8vIGF1dGhlbnRpY2F0ZWQgdXNlciBpcyBjdXJyZW50bHkgcmVnaXN0ZXJlZC5cbiAgICAgICAgdGhpcy5pc0F1dGhlbnRpY2F0ZWQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gISFTZXNzaW9uLnVzZXI7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5nZXRMb2dnZWRJblVzZXIgPSBmdW5jdGlvbiAoZnJvbVNlcnZlcikge1xuXG4gICAgICAgICAgICAvLyBJZiBhbiBhdXRoZW50aWNhdGVkIHNlc3Npb24gZXhpc3RzLCB3ZVxuICAgICAgICAgICAgLy8gcmV0dXJuIHRoZSB1c2VyIGF0dGFjaGVkIHRvIHRoYXQgc2Vzc2lvblxuICAgICAgICAgICAgLy8gd2l0aCBhIHByb21pc2UuIFRoaXMgZW5zdXJlcyB0aGF0IHdlIGNhblxuICAgICAgICAgICAgLy8gYWx3YXlzIGludGVyZmFjZSB3aXRoIHRoaXMgbWV0aG9kIGFzeW5jaHJvbm91c2x5LlxuXG4gICAgICAgICAgICAvLyBPcHRpb25hbGx5LCBpZiB0cnVlIGlzIGdpdmVuIGFzIHRoZSBmcm9tU2VydmVyIHBhcmFtZXRlcixcbiAgICAgICAgICAgIC8vIHRoZW4gdGhpcyBjYWNoZWQgdmFsdWUgd2lsbCBub3QgYmUgdXNlZC5cblxuICAgICAgICAgICAgaWYgKHRoaXMuaXNBdXRoZW50aWNhdGVkKCkgJiYgZnJvbVNlcnZlciAhPT0gdHJ1ZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS53aGVuKFNlc3Npb24udXNlcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIE1ha2UgcmVxdWVzdCBHRVQgL3Nlc3Npb24uXG4gICAgICAgICAgICAvLyBJZiBpdCByZXR1cm5zIGEgdXNlciwgY2FsbCBvblN1Y2Nlc3NmdWxMb2dpbiB3aXRoIHRoZSByZXNwb25zZS5cbiAgICAgICAgICAgIC8vIElmIGl0IHJldHVybnMgYSA0MDEgcmVzcG9uc2UsIHdlIGNhdGNoIGl0IGFuZCBpbnN0ZWFkIHJlc29sdmUgdG8gbnVsbC5cbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9zZXNzaW9uJykudGhlbihvblN1Y2Nlc3NmdWxMb2dpbikuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLnNpZ251cCA9IGZ1bmN0aW9uKGNyZWRlbnRpYWxzKXtcbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvc2lnbnVwJywgY3JlZGVudGlhbHMpXG4gICAgICAgICAgICAudGhlbihvblN1Y2Nlc3NmdWxMb2dpbilcbiAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdCh7IG1lc3NhZ2U6ICdJbnZhbGlkIHNpZ251cCBjcmVkZW50aWFscy4nIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5sb2dpbiA9IGZ1bmN0aW9uIChjcmVkZW50aWFscykge1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9sb2dpbicsIGNyZWRlbnRpYWxzKVxuICAgICAgICAgICAgICAgIC50aGVuKG9uU3VjY2Vzc2Z1bExvZ2luKVxuICAgICAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QoeyBtZXNzYWdlOiAnSW52YWxpZCBsb2dpbiBjcmVkZW50aWFscy4nIH0pO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2xvZ291dCcpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIFNlc3Npb24uZGVzdHJveSgpO1xuICAgICAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChBVVRIX0VWRU5UUy5sb2dvdXRTdWNjZXNzKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuXG4gICAgfSk7XG5cbiAgICBhcHAuc2VydmljZSgnU2Vzc2lvbicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBVVRIX0VWRU5UUykge1xuXG4gICAgICAgIHZhciBzZWxmID0gdGhpcztcblxuICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5ub3RBdXRoZW50aWNhdGVkLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBzZWxmLmRlc3Ryb3koKTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHNlbGYuZGVzdHJveSgpO1xuICAgICAgICB9KTtcblxuICAgICAgICB0aGlzLmlkID0gbnVsbDtcbiAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcblxuICAgICAgICB0aGlzLmNyZWF0ZSA9IGZ1bmN0aW9uIChzZXNzaW9uSWQsIHVzZXIpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBzZXNzaW9uSWQ7XG4gICAgICAgICAgICB0aGlzLnVzZXIgPSB1c2VyO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMuZGVzdHJveSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBudWxsO1xuICAgICAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcbiAgICAgICAgfTtcblxuICAgIH0pO1xuXG59KSgpO1xuIiwiYXBwLmNvbnRyb2xsZXIoJ0hvbWVDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgYWxsRGJzLCAkc3RhdGUpIHtcblxuXHQkc2NvcGUuYWxsRGJzID0gYWxsRGJzO1xufSk7XG4iLCJhcHAuZmFjdG9yeSgnSG9tZUZhY3RvcnknLCBmdW5jdGlvbiAoJGh0dHApIHtcblxuXHR2YXIgSG9tZUZhY3RvcnkgPSB7fTtcblxuXHRmdW5jdGlvbiByZXNUb0RhdGEocmVzKSB7XG4gICAgICAgIHJldHVybiByZXMuZGF0YTtcbiAgICB9XG5cbiAgICBIb21lRmFjdG9yeS5nZXRBbGxEYnMgPSBmdW5jdGlvbigpe1xuICAgIFx0cmV0dXJuICRodHRwLmdldCgnL2FwaS9tYXN0ZXJkYicpXG4gICAgXHQudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgSG9tZUZhY3RvcnkuZGVsZXRlREIgPSBmdW5jdGlvbihuYW1lKXtcbiAgICBcdHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvbWFzdGVyZGIvJyArIG5hbWUpXG4gICAgXHQudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG5cdHJldHVybiBIb21lRmFjdG9yeTsgXG59KSIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ0hvbWUnLCB7XG4gICAgICAgIHVybDogJy9ob21lJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9Ib21lL0hvbWUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdIb21lQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgXHRhbGxEYnM6IGZ1bmN0aW9uKEhvbWVGYWN0b3J5KXtcbiAgICAgICAgXHRcdHJldHVybiBIb21lRmFjdG9yeS5nZXRBbGxEYnMoKTtcbiAgICAgICAgXHR9LFxuICAgICAgICAgICAgbG9nZ2VkSW5Vc2VyOiBmdW5jdGlvbiAoQXV0aFNlcnZpY2UpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KTtcbn0pOyIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2xhbmRpbmdQYWdlJywge1xuICAgICAgICB1cmw6ICcvJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9sYW5kaW5nUGFnZS9sYW5kaW5nUGFnZS5odG1sJ1xuICAgICAgICB9XG4gICAgKTtcblxufSk7IiwiYXBwLmNvbmZpZyhmdW5jdGlvbigkc3RhdGVQcm92aWRlcikge1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2xvZ2luJywge1xuICAgICAgICB1cmw6ICcvbG9naW4nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2xvZ2luL2xvZ2luLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnTG9naW5DdHJsJ1xuICAgIH0pO1xuXG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ0xvZ2luQ3RybCcsIGZ1bmN0aW9uKCRzY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICAgJHNjb3BlLmxvZ2luID0ge307XG4gICAgJHNjb3BlLmVycm9yID0gbnVsbDtcblxuICAgICRzY29wZS5zZW5kTG9naW4gPSBmdW5jdGlvbihsb2dpbkluZm8pIHtcblxuICAgICAgICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICAgICAgIEF1dGhTZXJ2aWNlLmxvZ2luKGxvZ2luSW5mbykudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbygnSG9tZScpO1xuICAgICAgICB9KS5jYXRjaChmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICRzY29wZS5lcnJvciA9ICdJbnZhbGlkIGxvZ2luIGNyZWRlbnRpYWxzLic7XG4gICAgICAgIH0pO1xuXG4gICAgfTtcblxufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ21lbWJlcnNPbmx5Jywge1xuICAgICAgICB1cmw6ICcvbWVtYmVycy1hcmVhJyxcbiAgICAgICAgdGVtcGxhdGU6ICc8aW1nIG5nLXJlcGVhdD1cIml0ZW0gaW4gc3Rhc2hcIiB3aWR0aD1cIjMwMFwiIG5nLXNyYz1cInt7IGl0ZW0gfX1cIiAvPicsXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uICgkc2NvcGUsIFNlY3JldFN0YXNoKSB7XG4gICAgICAgICAgICBTZWNyZXRTdGFzaC5nZXRTdGFzaCgpLnRoZW4oZnVuY3Rpb24gKHN0YXNoKSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnN0YXNoID0gc3Rhc2g7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSxcbiAgICAgICAgLy8gVGhlIGZvbGxvd2luZyBkYXRhLmF1dGhlbnRpY2F0ZSBpcyByZWFkIGJ5IGFuIGV2ZW50IGxpc3RlbmVyXG4gICAgICAgIC8vIHRoYXQgY29udHJvbHMgYWNjZXNzIHRvIHRoaXMgc3RhdGUuIFJlZmVyIHRvIGFwcC5qcy5cbiAgICAgICAgZGF0YToge1xuICAgICAgICAgICAgYXV0aGVudGljYXRlOiB0cnVlXG4gICAgICAgIH1cbiAgICB9KTtcblxufSk7XG5cbmFwcC5mYWN0b3J5KCdTZWNyZXRTdGFzaCcsIGZ1bmN0aW9uICgkaHR0cCkge1xuXG4gICAgdmFyIGdldFN0YXNoID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL21lbWJlcnMvc2VjcmV0LXN0YXNoJykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5kYXRhO1xuICAgICAgICB9KTtcbiAgICB9O1xuXG4gICAgcmV0dXJuIHtcbiAgICAgICAgZ2V0U3Rhc2g6IGdldFN0YXNoXG4gICAgfTtcblxufSk7IiwiJ3VzZSBzdHJpY3QnO1xuXG5hcHAuZGlyZWN0aXZlKCdvYXV0aEJ1dHRvbicsIGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIHtcbiAgICBzY29wZToge1xuICAgICAgcHJvdmlkZXJOYW1lOiAnQCdcbiAgICB9LFxuICAgIHJlc3RyaWN0OiAnRScsXG4gICAgdGVtcGxhdGVVcmw6ICcvanMvb2F1dGgvb2F1dGgtYnV0dG9uLmh0bWwnXG4gIH1cbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdzaWdudXAnLCB7XG4gICAgICAgIHVybDogJy9zaWdudXAnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3NpZ251cC9zaWdudXAuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdTaWdudXBDdHJsJ1xuICAgIH0pO1xuXG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ1NpZ251cEN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBBdXRoU2VydmljZSwgJHN0YXRlKSB7XG5cbiAgICAkc2NvcGUuc2lnbnVwID0ge307XG4gICAgJHNjb3BlLmVycm9yID0gbnVsbDtcblxuICAgICRzY29wZS5zZW5kU2lnbnVwID0gZnVuY3Rpb24gKHNpZ251cEluZm8pIHtcbiAgICAgICAgJHNjb3BlLmVycm9yID0gbnVsbDtcbiAgICAgICAgQXV0aFNlcnZpY2Uuc2lnbnVwKHNpZ251cEluZm8pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKCdob21lJyk7XG4gICAgICAgIH0pLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICRzY29wZS5lcnJvciA9ICdPb3BzLCBjYW5ub3Qgc2lnbiB1cCB3aXRoIHRob3NlIGNyZWRlbnRpYWxzLic7XG4gICAgICAgIH0pO1xuXG4gICAgfTtcblxufSk7XG4iLCJhcHAuY29udHJvbGxlcignQXNzb2NpYXRpb25JbnN0YW5jZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCAkdWliTW9kYWxJbnN0YW5jZSwgZm9yZWlnbkNvbHMsIFRhYmxlRmFjdG9yeSwgSG9tZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgJHN0YXRlLCBmb3JUYWJsZSwgZm9yVGFibGVOYW1lLCBjdXJyVGFibGUsIGNvbE5hbWUsIGlkMSkge1xuXG4gICRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lO1xuXG4gICRzY29wZS5zaW5nbGVUYWJsZSA9IGZvclRhYmxlO1xuXG4gICRzY29wZS5UYWJsZU5hbWUgPSBmb3JUYWJsZU5hbWU7XG5cbiAgJHNjb3BlLmN1cnJUYWJsZSA9IGN1cnJUYWJsZTtcblxuICAkc2NvcGUuY29sTmFtZSA9IGNvbE5hbWU7XG5cbiAgJHNjb3BlLmlkMSA9IGlkMTtcblxuICAkc2NvcGUuc2V0U2VsZWN0ZWQgPSBmdW5jdGlvbigpe1xuXG4gICAgJHNjb3BlLmN1cnJSb3cgPSB0aGlzLnJvdztcbiAgICBjb25zb2xlLmxvZygkc2NvcGUuY3VyclJvdyk7XG4gIH1cblxuIFxuXG4gIGZ1bmN0aW9uIENyZWF0ZUNvbHVtbnMoKXtcbiAgICAkc2NvcGUuY29sdW1ucyA9IFtdO1xuICAgIHZhciB0YWJsZSA9IGZvclRhYmxlWzBdO1xuXG5cbiAgICBmb3IodmFyIHByb3AgaW4gdGFibGUpe1xuICAgICAgaWYocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jyl7XG4gICAgICAgICRzY29wZS5jb2x1bW5zLnB1c2gocHJvcCk7ICBcbiAgICAgIH0gXG4gICAgfVxuICB9XG5cbiAgICBDcmVhdGVDb2x1bW5zKCk7XG5cblxuICAgIC8vdGhpcyBmdW5jdGlvbiB3aWxsIHJlIHJ1biB3aGVuIHRoZSBmaWx0ZXIgZnVuY3Rpb24gaXMgaW52b2tlZCwgaW4gb3JkZXIgdG8gcmVwb3B1bGF0ZSB0aGUgdGFibGVcbiAgICBmdW5jdGlvbiBDcmVhdGVSb3dzKCkge1xuICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheSA9IFtdO1xuICAgICAgICBmb3JUYWJsZS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgdmFyIHJvd1ZhbHVlcyA9IFtdO1xuICAgICAgICAgICAgZm9yICh2YXIgcHJvcCBpbiByb3cpIHtcbiAgICAgICAgICAgICAgICBpZiAocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jykgcm93VmFsdWVzLnB1c2gocm93W3Byb3BdKVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkucHVzaChyb3dWYWx1ZXMpXG4gICAgICAgIH0pXG4gICAgfVxuXG4gICAgLy8gU29ydCB0aGUgdmFsdWVzIGluIHNpbmdsZVRhYmxlIHNvIHRoYXQgYWxsIHRoZSB2YWx1ZXMgZm9yIGEgZ2l2ZW4gcm93IGFyZSBncm91cGVkXG4gICAgQ3JlYXRlUm93cygpO1xuXG5cbiAgJHNjb3BlLnNldEZvcmVpZ25LZXkgPSBmdW5jdGlvbihkYk5hbWUsIHRibE5hbWUsIGNvbE5hbWUsIGlkMSwgaWQyKXtcbiAgICAkdWliTW9kYWxJbnN0YW5jZS5jbG9zZSgpO1xuICAgIFRhYmxlRmFjdG9yeS5zZXRGb3JlaWduS2V5KGRiTmFtZSwgdGJsTmFtZSwgY29sTmFtZSwgaWQxLCBpZDIpXG4gICAgLnRoZW4oZnVuY3Rpb24oKXtcbiAgICAgICAgJHN0YXRlLmdvKCdUYWJsZS5TaW5nbGUnLCB7IGRiTmFtZTogJHNjb3BlLmRiTmFtZSwgdGFibGVOYW1lOiAkc2NvcGUuY3VyclRhYmxlIH0sIHsgcmVsb2FkOiB0cnVlIH0pXG4gICAgfSlcbiAgfVxuXG5cblxuICAkc2NvcGUub2sgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoJHNjb3BlLnNlbGVjdGVkLml0ZW0pO1xuICB9O1xuXG4gICRzY29wZS5jYW5jZWwgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuZGlzbWlzcygnY2FuY2VsJyk7XG4gIH07XG59KTsiLCJhcHAuY29udHJvbGxlcignZGVsZXRlREJDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHVpYk1vZGFsLCAkbG9nKSB7XG5cbiAgJHNjb3BlLml0ZW1zID0gWydpdGVtMScsICdpdGVtMicsICdpdGVtMyddO1xuXG4gICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9IHRydWU7XG5cbiAgJHNjb3BlLm9wZW4gPSBmdW5jdGlvbiAoc2l6ZSkge1xuXG4gICAgdmFyIG1vZGFsSW5zdGFuY2UgPSAkdWliTW9kYWwub3Blbih7XG4gICAgICBhbmltYXRpb246ICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCxcbiAgICAgIHRlbXBsYXRlVXJsOiAnZGVsZXRlREJDb250ZW50Lmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ2RlbGV0ZURCSW5zdGFuY2VDdHJsJyxcbiAgICAgIHNpemU6IHNpemUsXG4gICAgICByZXNvbHZlOiB7XG4gICAgICAgIGl0ZW1zOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgcmV0dXJuICRzY29wZS5pdGVtcztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbiAoc2VsZWN0ZWRJdGVtKSB7XG4gICAgICAkc2NvcGUuc2VsZWN0ZWQgPSBzZWxlY3RlZEl0ZW07XG4gICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgJGxvZy5pbmZvKCdNb2RhbCBkaXNtaXNzZWQgYXQ6ICcgKyBuZXcgRGF0ZSgpKTtcbiAgICB9KTtcbiAgfTtcblxuICAkc2NvcGUudG9nZ2xlQW5pbWF0aW9uID0gZnVuY3Rpb24gKCkge1xuICAgICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9ICEkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQ7XG4gIH07XG5cbn0pO1xuXG5hcHAuY29udHJvbGxlcignZGVsZXRlREJJbnN0YW5jZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCAkdWliTW9kYWxJbnN0YW5jZSwgaXRlbXMsIFRhYmxlRmFjdG9yeSwgSG9tZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgJHN0YXRlKSB7XG5cblxuICAkc2NvcGUuZHJvcERiVGV4dCA9ICdEUk9QIERBVEFCQVNFJ1xuICAkc2NvcGUuZGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZTtcblxuICAkc2NvcGUuZGVsZXRlVGhlRGIgPSBmdW5jdGlvbigpe1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmNsb3NlKCRzY29wZS5zZWxlY3RlZC5pdGVtKTtcbiAgICBUYWJsZUZhY3RvcnkuZGVsZXRlRGIoJHNjb3BlLmRiTmFtZSlcbiAgICAudGhlbihmdW5jdGlvbigpe1xuICAgICAgSG9tZUZhY3RvcnkuZGVsZXRlREIoJHNjb3BlLmRiTmFtZSlcbiAgICB9KVxuICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgJHN0YXRlLmdvKCdIb21lJywge30sIHtyZWxvYWQgOiB0cnVlfSlcbiAgICB9KVxuICB9XG5cbiAgJHNjb3BlLml0ZW1zID0gaXRlbXM7XG4gICRzY29wZS5zZWxlY3RlZCA9IHtcbiAgICBpdGVtOiAkc2NvcGUuaXRlbXNbMF1cbiAgfTtcblxuICAkc2NvcGUub2sgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoJHNjb3BlLnNlbGVjdGVkLml0ZW0pO1xuICB9O1xuXG4gICRzY29wZS5jYW5jZWwgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuZGlzbWlzcygnY2FuY2VsJyk7XG4gIH07XG59KTsiLCJhcHAuY29udHJvbGxlcignRGVsZXRlRGJDdHJsJywgZnVuY3Rpb24gKCRzY29wZSkge1xuXG4gICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9IHRydWU7XG5cbiAgJHNjb3BlLm9wZW4gPSBmdW5jdGlvbiAoc2l6ZSkge1xuXG4gICAgdmFyIG1vZGFsSW5zdGFuY2UgPSAkdWliTW9kYWwub3Blbih7XG4gICAgICBhbmltYXRpb246ICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCxcbiAgICAgIHRlbXBsYXRlVXJsOiAnZGVsZXRlRGJDb250ZW50Lmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0RlbGV0ZURiSW5zdGFuY2VDdHJsJyxcbiAgICAgIHNpemU6IHNpemUsXG4gICAgICByZXNvbHZlOiB7XG4gICAgICAgIGl0ZW1zOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgcmV0dXJuICRzY29wZS5pdGVtcztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbiAoc2VsZWN0ZWRJdGVtKSB7XG4gICAgICAkc2NvcGUuc2VsZWN0ZWQgPSBzZWxlY3RlZEl0ZW07XG4gICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgJGxvZy5pbmZvKCdNb2RhbCBkaXNtaXNzZWQgYXQ6ICcgKyBuZXcgRGF0ZSgpKTtcbiAgICB9KTtcbiAgfTtcblxufSk7XG5cblxuYXBwLmNvbnRyb2xsZXIoJ0RlbGV0ZURiSW5zdGFuY2VDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHVpYk1vZGFsSW5zdGFuY2UsIGl0ZW1zLCAkc3RhdGVQYXJhbXMsIFRhYmxlRmFjdG9yeSkge1xuXG4gICRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lXG5cbiAgJHNjb3BlLmRyb3BEYXRhYmFzZSA9ICdEUk9QIERBVEFCQVNFJ1xuXG4gICRzY29wZS5kZWxldGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgVGFibGVGYWN0b3J5LmRlbGV0ZURiKCRzY29wZS5kYk5hbWUpXG4gICAgLy8gJHN0YXRlLmdvKCdIb21lJywge30sIHtyZWxvYWQgOiB0cnVlfSlcbiAgfTtcblxuICAkc2NvcGUuY2FuY2VsID0gZnVuY3Rpb24gKCkge1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmRpc21pc3MoJ2NhbmNlbCcpO1xuICB9O1xufSk7IiwiYXBwLmNvbnRyb2xsZXIoJ0pvaW5UYWJsZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgam9pblRhYmxlKSB7XG5cbiAgICAkc2NvcGUuam9pblRhYmxlID0gam9pblRhYmxlO1xuXG5cblx0ZnVuY3Rpb24gQ3JlYXRlQ29sdW1ucygpe1xuXHRcdCRzY29wZS5jb2x1bW5zID0gW107XG5cdFx0dmFyIHRhYmxlID0gJHNjb3BlLmpvaW5UYWJsZVswXTtcblxuXG5cdFx0Zm9yKHZhciBwcm9wIGluIHRhYmxlKXtcblx0XHRcdGlmKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpe1xuXHRcdFx0XHQkc2NvcGUuY29sdW1ucy5wdXNoKHByb3ApO1x0XG5cdFx0XHR9IFxuXHRcdH1cblx0fVxuXG4gICAgQ3JlYXRlQ29sdW1ucygpO1xuXG5cbiAgICAvL3RoaXMgZnVuY3Rpb24gd2lsbCByZSBydW4gd2hlbiB0aGUgZmlsdGVyIGZ1bmN0aW9uIGlzIGludm9rZWQsIGluIG9yZGVyIHRvIHJlcG9wdWxhdGUgdGhlIHRhYmxlXG4gICAgZnVuY3Rpb24gQ3JlYXRlUm93cygpIHtcbiAgICBcdHZhciBhbGlhcztcbiAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkgPSBbXTtcbiAgICAgICAgam9pblRhYmxlLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICB2YXIgcm93VmFsdWVzID0gW107XG4gICAgICAgICAgICBmb3IgKHZhciBwcm9wIGluIHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKSByb3dWYWx1ZXMucHVzaChyb3dbcHJvcF0pXG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheS5wdXNoKHJvd1ZhbHVlcylcbiAgICAgICAgfSlcbiAgICB9XG5cbiAgICAvLyBTb3J0IHRoZSB2YWx1ZXMgaW4gc2luZ2xlVGFibGUgc28gdGhhdCBhbGwgdGhlIHZhbHVlcyBmb3IgYSBnaXZlbiByb3cgYXJlIGdyb3VwZWRcbiAgICBDcmVhdGVSb3dzKCk7XG5cblxufSkiLCJhcHAuY29udHJvbGxlcignUXVlcnlUYWJsZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuXG4gICAgJHNjb3BlLnFGaWx0ZXIgPSBmdW5jdGlvbihyZWZlcmVuY2VTdHJpbmcsIHZhbCl7XG4gICAgICAgIGlmKCFyZWZlcmVuY2VTdHJpbmcpIHJldHVybiB0cnVlO1xuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIGZvcih2YXIgcHJvcCBpbiB2YWwpe1xuICAgICAgICAgICAgICAgIHZhciBjZWxsVmFsID0gdmFsW3Byb3BdLnRvU3RyaW5nKCkudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgICAgICB2YXIgc2VhcmNoVmFsID0gcmVmZXJlbmNlU3RyaW5nLnRvU3RyaW5nKCkudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhjZWxsVmFsLCBzZWFyY2hWYWwsIGNlbGxWYWwuaW5kZXhPZihzZWFyY2hWYWwpICE9PSAtMSlcbiAgICAgICAgICAgICAgICBpZihjZWxsVmFsLmluZGV4T2Yoc2VhcmNoVmFsKSAhPT0gLTEpIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbn0pIiwiYXBwLmNvbnRyb2xsZXIoJ1NpbmdsZVRhYmxlQ3RybCcsIGZ1bmN0aW9uKCRzY29wZSwgVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMsIHNpbmdsZVRhYmxlLCAkd2luZG93LCAkc3RhdGUsICR1aWJNb2RhbCwgYXNzb2NpYXRpb25zLCAkbG9nKSB7XG5cbiAgICAvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vUHV0dGluZyBzdHVmZiBvbiBzY29wZS8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgICRzY29wZS50aGVEYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lO1xuICAgICRzY29wZS50aGVUYWJsZU5hbWUgPSAkc3RhdGVQYXJhbXMudGFibGVOYW1lO1xuICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHNpbmdsZVRhYmxlWzBdLnNvcnQoZnVuY3Rpb24oYSwgYil7XG4gICAgICAgIGlmKGEuaWQgPiBiLmlkKSByZXR1cm4gMTtcbiAgICAgICAgaWYoYS5pZCA8IGIuaWQpIHJldHVybiAtMTtcbiAgICAgICAgcmV0dXJuIDA7XG4gICAgfSk7XG4gICAgJHNjb3BlLnNlbGVjdGVkQWxsID0gZmFsc2U7XG4gICAgJHNjb3BlLmFzc29jaWF0aW9ucyA9IGFzc29jaWF0aW9ucztcblxuXG4gICAgZnVuY3Rpb24gZm9yZWlnbkNvbHVtbk9iaigpIHtcbiAgICAgICAgdmFyIGZvcmVpZ25Db2xzID0ge307XG4gICAgICAgICRzY29wZS5hc3NvY2lhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIGlmIChyb3cuVGFibGUxID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmIHJvdy5SZWxhdGlvbnNoaXAxID09PSAnaGFzT25lJykge1xuICAgICAgICAgICAgICAgIGZvcmVpZ25Db2xzW3Jvdy5BbGlhczFdID0gcm93LlRhYmxlMlxuICAgICAgICAgICAgfSBlbHNlIGlmIChyb3cuVGFibGUyID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmIHJvdy5SZWxhdGlvbnNoaXAyID09PSAnaGFzT25lJykge1xuICAgICAgICAgICAgICAgIGZvcmVpZ25Db2xzW3Jvdy5BbGlhczJdID0gcm93LlRhYmxlMVxuICAgICAgICAgICAgfVxuICAgICAgICB9KVxuICAgICAgICAkc2NvcGUuZm9yZWlnbkNvbHMgPSBmb3JlaWduQ29scztcbiAgICB9XG5cbiAgICBmb3JlaWduQ29sdW1uT2JqKCk7XG5cblxuICAgICRzY29wZS5jdXJyZW50VGFibGUgPSAkc3RhdGVQYXJhbXM7XG5cbiAgICAkc2NvcGUubXlJbmRleCA9IDE7XG5cbiAgICAkc2NvcGUuaWRzID0gJHNjb3BlLnNpbmdsZVRhYmxlLm1hcChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgcmV0dXJuIHJvdy5pZDtcbiAgICB9KVxuXG4gICAgLy9kZWxldGUgYSByb3cgXG4gICAgJHNjb3BlLnNob3dEZWxldGUgPSBmYWxzZTtcbiAgICAkc2NvcGUudG9nZ2xlRGVsZXRlID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICRzY29wZS5zaG93RGVsZXRlID0gISRzY29wZS5zaG93RGVsZXRlXG4gICAgfVxuXG4gICAgJHNjb3BlLmRlbGV0ZVNlbGVjdGVkID0gZnVuY3Rpb24oZGIsIHRhYmxlLCBpbnN0YW5jZUFycmF5KSB7XG4gICAgICAgIGZvcih2YXIgaSA9IGluc3RhbmNlQXJyYXkubGVuZ3RoLTE7IGkgPj0gMDsgaS0tKXtcbiAgICAgICAgICAgIHZhciByb3cgPSBpbnN0YW5jZUFycmF5W2ldO1xuICAgICAgICAgICAgdmFyIGxlbmd0aCA9IGk7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhyb3cpICAgICAgIFxuICAgICAgICAgICAgaWYgKHJvdy5zZWxlY3RlZCkge1xuICAgICAgICAgICAgICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVSb3coZGIsIHRhYmxlLCByb3dbJ3ZhbHVlcyddWzBdWyd2YWx1ZSddLCBsZW5ndGgpXG4gICAgICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0O1xuICAgICAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgICRzY29wZS5zaG93RGVsZXRlID0gZmFsc2U7XG4gICAgfVxuXG4gICAgJHNjb3BlLnNlbGVjdEFsbCA9IGZ1bmN0aW9uKGluc3RhbmNlQXJyYXkpIHtcbiAgICAgICAgaWYgKCRzY29wZS5zZWxlY3RlZEFsbCkge1xuICAgICAgICAgICAgaW5zdGFuY2VBcnJheS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgICAgIHJvdy5zZWxlY3RlZCA9IHRydWU7XG4gICAgICAgICAgICB9KVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgaW5zdGFuY2VBcnJheS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgICAgIHJvdy5zZWxlY3RlZCA9IGZhbHNlO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS51bmNoZWNrU2VsZWN0QWxsID0gZnVuY3Rpb24oaW5zdGFuY2VBcnJheSkge1xuICAgICAgICBpZiAoJHNjb3BlLnNlbGVjdGVkQWxsID09PSB0cnVlKSB7XG4gICAgICAgICAgICAkc2NvcGUuc2VsZWN0ZWRBbGwgPSBmYWxzZTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS5yZW1vdmVSb3cgPSBmdW5jdGlvbihkYiwgdGFibGUsIHJvdywgaW5zdGFuY2VBcnJheSkge1xuICAgICAgICB2YXIgbGVuZ3RoID0gaW5zdGFuY2VBcnJheS5sZW5ndGggLSAxO1xuICAgICAgICBUYWJsZUZhY3RvcnkucmVtb3ZlUm93KGRiLCB0YWJsZSwgcm93LCBsZW5ndGgpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgfSlcbiAgICB9XG5cbiAgICAkc2NvcGUucmVtb3ZlQ29sdW1uID0gZnVuY3Rpb24oZGIsIHRhYmxlLCBjb2x1bW5OYW1lKSB7XG4gICAgICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVDb2x1bW4oZGIsIHRhYmxlLCBjb2x1bW5OYW1lKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0O1xuICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICBDcmVhdGVDb2x1bW5zKCk7XG4gICAgICAgICAgICB9KVxuICAgIH1cblxuICAgICRzY29wZS5uZXdSb3cgPSBmdW5jdGlvbihkYiwgdGFibGUsIGFycikge1xuICAgICAgICB2YXIgYWxsSWRzID0gW107XG4gICAgICAgIGFyci5mb3JFYWNoKGZ1bmN0aW9uKHJvd0RhdGEpIHtcbiAgICAgICAgICAgIGFsbElkcy5wdXNoKHJvd0RhdGEudmFsdWVzWzBdLnZhbHVlKVxuICAgICAgICB9KVxuICAgICAgICB2YXIgc29ydGVkID0gYWxsSWRzLnNvcnQoZnVuY3Rpb24oYSwgYikge1xuICAgICAgICAgICAgcmV0dXJuIGIgLSBhXG4gICAgICAgIH0pXG4gICAgICAgIGlmIChzb3J0ZWQubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgVGFibGVGYWN0b3J5LmFkZFJvdyhkYiwgdGFibGUsIHNvcnRlZFswXSArIDEpXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHJlc3VsdDtcbiAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgIH0pXG5cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIFRhYmxlRmFjdG9yeS5hZGRSb3coZGIsIHRhYmxlLCAxKVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLmFkZENvbHVtbiA9IGZ1bmN0aW9uKGRiLCB0YWJsZSkge1xuICAgICAgICB2YXIgY29sTnVtcyA9ICRzY29wZS5jb2x1bW5zLmpvaW4oJyAnKS5tYXRjaCgvXFxkKy9nKTtcbiAgICAgICAgaWYgKGNvbE51bXMpIHtcbiAgICAgICAgICAgIHZhciBzb3J0ZWROdW1zID0gY29sTnVtcy5zb3J0KGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gYiAtIGFcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB2YXIgbnVtSW5OZXcgPSBOdW1iZXIoc29ydGVkTnVtc1swXSkgKyAxO1xuICAgICAgICAgICAgdmFyIG5hbWVOZXdDb2wgPSAnQ29sdW1uICcgKyBudW1Jbk5ldy50b1N0cmluZygpO1xuXG4gICAgICAgICAgICBUYWJsZUZhY3RvcnkuYWRkQ29sdW1uKGRiLCB0YWJsZSwgbmFtZU5ld0NvbClcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSgkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKVxuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24odGhlVGFibGUpIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gdGhlVGFibGVbMF07XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZUNvbHVtbnMoKTtcbiAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB2YXIgbmV4dENvbE51bSA9ICRzY29wZS5jb2x1bW5zLmxlbmd0aCArIDE7XG4gICAgICAgICAgICB2YXIgbmV3Q29sTmFtZSA9ICdDb2x1bW4gJyArIG5leHRDb2xOdW07XG4gICAgICAgICAgICBUYWJsZUZhY3RvcnkuYWRkQ29sdW1uKGRiLCB0YWJsZSwgJ0NvbHVtbiAxJylcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSgkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKVxuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24odGhlVGFibGUpIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gdGhlVGFibGVbMF07XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZUNvbHVtbnMoKTtcbiAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgIH1cblxuICAgIH1cblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9Pcmdhbml6aW5nIHN0dWZmIGludG8gYXJyYXlzLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuXG4gICAgLy8gR2V0IGFsbCBvZiB0aGUgY29sdW1ucyB0byBjcmVhdGUgdGhlIGNvbHVtbnMgb24gdGhlIGJvb3RzdHJhcCB0YWJsZVxuXG4gICAgZnVuY3Rpb24gQ3JlYXRlQ29sdW1ucygpIHtcbiAgICAgICAgJHNjb3BlLmNvbHVtbnMgPSBbXTtcbiAgICAgICAgJHNjb3BlLm9yaWdpbmFsQ29sVmFscyA9IFtdO1xuICAgICAgICB2YXIgdGFibGUgPSAkc2NvcGUuc2luZ2xlVGFibGVbMF07XG5cblxuICAgICAgICBmb3IgKHZhciBwcm9wIGluIHRhYmxlKSB7XG4gICAgICAgICAgICBpZiAocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jykge1xuICAgICAgICAgICAgICAgICRzY29wZS5jb2x1bW5zLnB1c2gocHJvcCk7XG4gICAgICAgICAgICAgICAgJHNjb3BlLm9yaWdpbmFsQ29sVmFscy5wdXNoKHByb3ApO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgQ3JlYXRlQ29sdW1ucygpO1xuXG4gICAgZnVuY3Rpb24gY3JlYXRlVmlydHVhbENvbHVtbnMoKSB7XG4gICAgICAgIGlmICgkc2NvcGUuYXNzb2NpYXRpb25zLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgICRzY29wZS52aXJ0dWFsQ29sdW1ucyA9IFtdO1xuICAgICAgICAgICAgJHNjb3BlLmFzc29jaWF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChyb3cuVGFibGUxID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmIHJvdy5SZWxhdGlvbnNoaXAxID09PSAnaGFzTWFueScpIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHZpcnR1YWwgPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5uYW1lID0gcm93LkFsaWFzMTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHJvdy5UaHJvdWdoKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLnRhYmxlID0gcm93LlRocm91Z2g7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLmNvbHVtbmtleSA9IHJvdy5BbGlhczE7XG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLnRhYmxlID0gcm93LlRhYmxlMjtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwuY29sdW1ua2V5ID0gcm93LkFsaWFzMjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAkc2NvcGUudmlydHVhbENvbHVtbnMucHVzaCh2aXJ0dWFsKTtcbiAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKHJvdy5UYWJsZTIgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgcm93LlJlbGF0aW9uc2hpcDIgPT09ICdoYXNNYW55Jykge1xuICAgICAgICAgICAgICAgICAgICB2YXIgdmlydHVhbCA9IHt9O1xuICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLm5hbWUgPSByb3cuQWxpYXMyO1xuICAgICAgICAgICAgICAgICAgICBpZiAocm93LlRocm91Z2gpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwudGFibGUgPSByb3cuVGhyb3VnaDtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwuY29sdW1ua2V5ID0gcm93LkFsaWFzMjtcbiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwudGFibGUgPSByb3cuVGFibGUxO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5jb2x1bW5rZXkgPSByb3cuQWxpYXMxO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS52aXJ0dWFsQ29sdW1ucy5wdXNoKHZpcnR1YWwpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBjcmVhdGVWaXJ0dWFsQ29sdW1ucygpO1xuXG4gICAgLy90aGlzIGZ1bmN0aW9uIHdpbGwgcmUgcnVuIHdoZW4gdGhlIGZpbHRlciBmdW5jdGlvbiBpcyBpbnZva2VkLCBpbiBvcmRlciB0byByZXBvcHVsYXRlIHRoZSB0YWJsZVxuICAgIGZ1bmN0aW9uIENyZWF0ZVJvd3MoKSB7XG4gICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5ID0gW107XG4gICAgICAgICRzY29wZS5zaW5nbGVUYWJsZS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgdmFyIHJvd1ZhbHVlcyA9IFtdO1xuICAgICAgICAgICAgdmFyIHJvd09iaiA9IHt9O1xuXG4gICAgICAgICAgICBmb3IgKHZhciBwcm9wIGluIHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKSByb3dWYWx1ZXMucHVzaCh7XG4gICAgICAgICAgICAgICAgICAgIGNvbDogcHJvcCxcbiAgICAgICAgICAgICAgICAgICAgdmFsdWU6IHJvd1twcm9wXVxuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByb3dPYmoudmFsdWVzID0gcm93VmFsdWVzO1xuICAgICAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkucHVzaChyb3dPYmopO1xuICAgICAgICB9KVxuICAgIH1cblxuICAgIC8vIFNvcnQgdGhlIHZhbHVlcyBpbiBzaW5nbGVUYWJsZSBzbyB0aGF0IGFsbCB0aGUgdmFsdWVzIGZvciBhIGdpdmVuIHJvdyBhcmUgZ3JvdXBlZFxuICAgIENyZWF0ZVJvd3MoKTtcbiAgICAvL3NlbmRzIHRoZSBmaWx0ZXJpbmcgcXVlcnkgYW5kIHRoZW4gcmUgcmVuZGVycyB0aGUgdGFibGUgd2l0aCBmaWx0ZXJlZCBkYXRhXG4gICAgJHNjb3BlLmZpbHRlciA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCBkYXRhKSB7XG4gICAgICAgIFRhYmxlRmFjdG9yeS5maWx0ZXIoZGJOYW1lLCB0YWJsZU5hbWUsIGRhdGEpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQuZGF0YTtcbiAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICB9KVxuICAgIH1cblxuXG4gICAgJHNjb3BlLmNoZWNrRm9yZWlnbiA9IGZ1bmN0aW9uKGNvbCkge1xuICAgICAgICByZXR1cm4gJHNjb3BlLmZvcmVpZ25Db2xzLmhhc093blByb3BlcnR5KGNvbCk7XG4gICAgfVxuXG4gICAgJHNjb3BlLmZpbmRQcmltYXJ5ID0gVGFibGVGYWN0b3J5LmZpbmRQcmltYXJ5O1xuXG4gICAgLy8qKioqKioqKioqKiogSW1wb3J0YW50ICoqKioqKioqKlxuICAgIC8vIE1ha2Ugc3VyZSB0byB1cGRhdGUgdGhlIHJvdyB2YWx1ZXMgQkVGT1JFIHRoZSBjb2x1bW4gbmFtZVxuICAgIC8vIFRoZSByb3dWYWxzVG9VcGRhdGUgYXJyYXkgc3RvcmVzIHRoZSB2YWx1ZXMgb2YgdGhlIE9SSUdJTkFMIGNvbHVtbiBuYW1lcyBzbyBpZiB0aGUgY29sdW1uIG5hbWUgaXMgdXBkYXRlZCBhZnRlciB0aGUgcm93IHZhbHVlLCB3ZSBzdGlsbCBoYXZlIHJlZmVyZW5jZSB0byB3aGljaCBjb2x1bW4gdGhlIHJvdyB2YWx1ZSByZWZlcmVuY2VzXG5cblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9VcGRhdGluZyBDb2x1bW4gU3R1ZmYvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG5cbiAgICAkc2NvcGUuY29sVmFsc1RvVXBkYXRlID0gW107XG5cbiAgICAkc2NvcGUudXBkYXRlQ29sdW1ucyA9IGZ1bmN0aW9uKG9sZCwgbmV3Q29sTmFtZSwgaSkge1xuICAgICAgICAkc2NvcGUuY29sdW1uc1tpXSA9IG5ld0NvbE5hbWU7XG5cbiAgICAgICAgdmFyIGNvbE9iaiA9IHsgb2xkVmFsOiAkc2NvcGUub3JpZ2luYWxDb2xWYWxzW2ldLCBuZXdWYWw6IG5ld0NvbE5hbWUgfTtcblxuICAgICAgICAvLyBpZiB0aGVyZSBpcyBub3RoaW5nIGluIHRoZSBhcnJheSB0byB1cGRhdGUsIHB1c2ggdGhlIHVwZGF0ZSBpbnRvIGl0XG4gICAgICAgIGlmICgkc2NvcGUuY29sVmFsc1RvVXBkYXRlLmxlbmd0aCA9PT0gMCkgeyAkc2NvcGUuY29sVmFsc1RvVXBkYXRlLnB1c2goY29sT2JqKTsgfSBlbHNlIHtcbiAgICAgICAgICAgIGZvciAodmFyIGUgPSAwOyBlIDwgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZS5sZW5ndGg7IGUrKykge1xuICAgICAgICAgICAgICAgIGlmICgkc2NvcGUuY29sVmFsc1RvVXBkYXRlW2VdLm9sZFZhbCA9PT0gY29sT2JqLm9sZFZhbCkge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuY29sVmFsc1RvVXBkYXRlW2VdID0gY29sT2JqO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZS5wdXNoKGNvbE9iaik7XG4gICAgICAgIH1cbiAgICAgICAgLy8gY2hlY2sgdG8gc2VlIGlmIHRoZSByb3cgaXMgYWxyZWFkeSBzY2hlZHVsZWQgdG8gYmUgdXBkYXRlZCwgaWYgaXQgaXMsIHRoZW4gdXBkYXRlIGl0IHdpdGggdGhlIG5ldyB0aGluZyB0byBiZSB1cGRhdGVkXG4gICAgfVxuXG4gICAgLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1VwZGF0aW5nIFJvdyBTdHVmZi8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgICRzY29wZS5yb3dWYWxzVG9VcGRhdGUgPSBbXTtcblxuICAgICRzY29wZS51cGRhdGVSb3cgPSBmdW5jdGlvbihvbGQsIG5ld0NlbGwsIHJvdywgaSwgail7XG4gICAgICAgIHZhciBjb2xzID0gJHNjb3BlLm9yaWdpbmFsQ29sVmFscztcbiAgICAgICAgdmFyIGZvdW5kID0gZmFsc2U7XG4gICAgICAgIHZhciBjb2xOYW1lID0gY29sc1tqXTtcbiAgICAgICAgZm9yKHZhciBrID0gMDsgayA8ICRzY29wZS5yb3dWYWxzVG9VcGRhdGUubGVuZ3RoOyBrKyspe1xuICAgICAgICAgICAgdmFyIG9iaiA9ICRzY29wZS5yb3dWYWxzVG9VcGRhdGVba107XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhvYmopXG4gICAgICAgICAgICBpZihvYmpbJ2lkJ10gPT09IGkpe1xuICAgICAgICAgICAgICAgIGZvdW5kID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICBpZihvYmpbY29sTmFtZV0pIG9ialtjb2xOYW1lXSA9IG5ld0NlbGw7XG4gICAgICAgICAgICAgICAgb2JqW2NvbE5hbWVdID0gbmV3Q2VsbDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBpZighZm91bmQpIHtcbiAgICAgICAgICAgIHZhciByb3dPYmogPSB7fTtcbiAgICAgICAgICAgIHJvd09ialsnaWQnXSA9IGk7XG4gICAgICAgICAgICByb3dPYmpbY29sTmFtZV0gPSBuZXdDZWxsO1xuICAgICAgICAgICAgJHNjb3BlLnJvd1ZhbHNUb1VwZGF0ZS5wdXNoKHJvd09iailcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS51cGRhdGVCYWNrZW5kID0gZnVuY3Rpb24oKSB7XG4gICAgICAgIHZhciBkYXRhID0geyByb3dzOiAkc2NvcGUucm93VmFsc1RvVXBkYXRlLCBjb2x1bW5zOiAkc2NvcGUuY29sVmFsc1RvVXBkYXRlIH1cbiAgICAgICAgVGFibGVGYWN0b3J5LnVwZGF0ZUJhY2tlbmQoJHNjb3BlLnRoZURiTmFtZSwgJHNjb3BlLnRoZVRhYmxlTmFtZSwgZGF0YSk7XG4gICAgfVxuXG5cbiAgICAkc2NvcGUuZGVsZXRlVGFibGUgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgVGFibGVGYWN0b3J5LmRlbGV0ZVRhYmxlKCRzY29wZS5jdXJyZW50VGFibGUpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAkc3RhdGUuZ28oJ1RhYmxlJywgeyBkYk5hbWU6ICRzY29wZS50aGVEYk5hbWUgfSwgeyByZWxvYWQ6IHRydWUgfSlcbiAgICAgICAgICAgIH0pXG4gICAgfVxuXG4gICAgLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1F1ZXJ5aW5nIFN0dWZmLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuXG4gICAgJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9ucyA9IFtdO1xuXG4gICAgJHNjb3BlLnRhYmxlc1RvUXVlcnkgPSBbXTtcblxuICAgIGFzc29jaWF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICBpZiAocm93LlRhYmxlMSA9PT0gJHNjb3BlLnRoZVRhYmxlTmFtZSAmJiAkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zLmluZGV4T2Yocm93LlRhYmxlMikgPT0gLTEpIHtcbiAgICAgICAgICAgICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMucHVzaChyb3cuVGFibGUyKTtcbiAgICAgICAgfSBlbHNlIGlmIChyb3cuVGFibGUyID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMuaW5kZXhPZihyb3cuVGFibGUxKSA9PSAtMSkge1xuICAgICAgICAgICAgJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9ucy5wdXNoKHJvdy5UYWJsZTEpO1xuICAgICAgICB9XG4gICAgfSlcblxuICAgICRzY29wZS5nZXRBc3NvY2lhdGVkID0gZnVuY3Rpb24odmFsKSB7XG4gICAgICAgIGlmICgkc2NvcGUudGFibGVzVG9RdWVyeS5pbmRleE9mKCRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnNbdmFsXSkgPT09IC0xKSB7XG4gICAgICAgICAgICAkc2NvcGUudGFibGVzVG9RdWVyeS5wdXNoKCRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnNbdmFsXSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHZhciBpID0gJHNjb3BlLnRhYmxlc1RvUXVlcnkuaW5kZXhPZigkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zW3ZhbF0pO1xuICAgICAgICAgICAgJHNjb3BlLnRhYmxlc1RvUXVlcnkuc3BsaWNlKGksIDEpXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAkc2NvcGUuY29sdW1uc0ZvclF1ZXJ5ID0gW107XG5cbiAgICAkc2NvcGUuZ2V0Q29sdW1uc0ZvclRhYmxlID0gZnVuY3Rpb24oKSB7XG4gICAgICAgIHZhciBwcm9taXNlc0ZvckNvbHVtbnMgPSBbXTtcbiAgICAgICAgJHNjb3BlLnRhYmxlc1RvUXVlcnkuZm9yRWFjaChmdW5jdGlvbih0YWJsZU5hbWUpIHtcbiAgICAgICAgICAgIHJldHVybiBwcm9taXNlc0ZvckNvbHVtbnMucHVzaChUYWJsZUZhY3RvcnkuZ2V0Q29sdW1uc0ZvclRhYmxlKCRzY29wZS50aGVEYk5hbWUsIHRhYmxlTmFtZSkpXG4gICAgICAgIH0pXG4gICAgICAgIFByb21pc2UuYWxsKHByb21pc2VzRm9yQ29sdW1ucylcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKGNvbHVtbnMpIHtcbiAgICAgICAgICAgICAgICBjb2x1bW5zLmZvckVhY2goZnVuY3Rpb24oY29sdW1uKSB7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5jb2x1bW5zRm9yUXVlcnkucHVzaChjb2x1bW4pO1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuJGV2YWxBc3luYygpXG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIH0pXG5cbiAgICB9XG5cbiAgICB2YXIgc2VsZWN0ZWRDb2x1bW5zID0ge307XG4gICAgdmFyIHF1ZXJ5VGFibGU7XG5cbiAgICAkc2NvcGUuZ2V0RGF0YUZyb21Db2x1bW5zID0gZnVuY3Rpb24odmFsKSB7XG4gICAgICAgIGlmKCFzZWxlY3RlZENvbHVtbnMpIHNlbGVjdGVkQ29sdW1ucyA9IFtdO1xuXG4gICAgICAgIHZhciBjb2x1bW5OYW1lID0gJHNjb3BlLmNvbHVtbnNGb3JRdWVyeVswXVsnY29sdW1ucyddW3ZhbC5pXTtcbiAgICAgICAgdmFyIHRhYmxlTmFtZSA9IHZhbC50YWJsZU5hbWVcbiAgICAgICAgcXVlcnlUYWJsZSA9IHRhYmxlTmFtZTtcblxuICAgICAgICBpZiAoIXNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdKSBzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXSA9IFtdO1xuICAgICAgICBpZiAoc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0uaW5kZXhPZihjb2x1bW5OYW1lKSAhPT0gLTEpIHtcbiAgICAgICAgICAgIHNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdLnNwbGljZShzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXS5pbmRleE9mKGNvbHVtbk5hbWUpLCAxKVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0ucHVzaChjb2x1bW5OYW1lKTtcbiAgICAgICAgfVxuICAgICAgICAkc2NvcGUuc2VsZWN0ZWRDb2x1bW5zID0gc2VsZWN0ZWRDb2x1bW5zO1xuICAgIH1cblxuXG4gICAgLy8gUnVubmluZyB0aGUgcXVlcnkgKyByZW5kZXJpbmcgdGhlIHF1ZXJ5XG4gICAgJHNjb3BlLnJlc3VsdE9mUXVlcnkgPSBbXTtcblxuICAgICRzY29wZS5xdWVyeVJlc3VsdDtcblxuICAgICRzY29wZS5hcnIgPSBbXTtcblxuXG4gICAgLy8gdGhlVGFibGVOYW1lXG5cbiAgICAkc2NvcGUucnVuSm9pbiA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAvLyBkYk5hbWUsIHRhYmxlMSwgYXJyYXlPZlRhYmxlcywgc2VsZWN0ZWRDb2x1bW5zLCBhc3NvY2lhdGlvbnNcbiAgICAgICAgdmFyIGNvbHVtbnNUb1JldHVybiA9ICRzY29wZS5jb2x1bW5zLm1hcChmdW5jdGlvbihjb2xOYW1lKXtcbiAgICAgICAgICAgIHJldHVybiAkc2NvcGUudGhlVGFibGVOYW1lICsgJy4nICsgY29sTmFtZTtcbiAgICAgICAgfSlcbiAgICAgICAgZm9yKHZhciBwcm9wIGluICRzY29wZS5zZWxlY3RlZENvbHVtbnMpe1xuICAgICAgICAgICAkc2NvcGUuc2VsZWN0ZWRDb2x1bW5zW3Byb3BdLmZvckVhY2goZnVuY3Rpb24oY29sKXtcbiAgICAgICAgICAgICAgICBjb2x1bW5zVG9SZXR1cm4ucHVzaChwcm9wICsgJy4nICsgY29sKVxuICAgICAgICAgICB9KVxuICAgICAgICB9XG4gICAgICAgIFRhYmxlRmFjdG9yeS5ydW5Kb2luKCRzY29wZS50aGVEYk5hbWUsICRzY29wZS50aGVUYWJsZU5hbWUsICRzY29wZS50YWJsZXNUb1F1ZXJ5LCAkc2NvcGUuc2VsZWN0ZWRDb2x1bW5zLCAkc2NvcGUuYXNzb2NpYXRpb25zLCBjb2x1bW5zVG9SZXR1cm4pXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihxdWVyeVJlc3VsdCkge1xuICAgICAgICAgICAgICAgICRzY29wZS5xdWVyeVJlc3VsdCA9IHF1ZXJ5UmVzdWx0O1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnVGFibGUuU2luZ2xlLnF1ZXJ5Jyk7XG4gICAgICAgICAgICB9KVxuICAgIH1cblxuICAgICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9IHRydWU7XG5cbiAgICAkc2NvcGUub3BlbiA9IGZ1bmN0aW9uIChkYk5hbWUsIHRibE5hbWUsIGNvbCwgaW5kZXgpIHtcblxuICAgICAgdmFyIG1vZGFsSW5zdGFuY2UgPSAkdWliTW9kYWwub3Blbih7XG4gICAgICAgIGFuaW1hdGlvbjogJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkLFxuICAgICAgICBiYWNrZHJvcDogZmFsc2UsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvYXNzb2NpYXRpb24ubW9kYWwuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdBc3NvY2lhdGlvbkluc3RhbmNlQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICBmb3JlaWduQ29sczogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuICRzY29wZS5mb3JlaWduQ29scztcbiAgICAgICAgICB9LFxuICAgICAgICAgIGZvclRhYmxlOiBmdW5jdGlvbihUYWJsZUZhY3Rvcnkpe1xuICAgICAgICAgICAgY29uc29sZS5sb2codGJsTmFtZSlcbiAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZmluZFByaW1hcnkoZGJOYW1lLCB0YmxOYW1lKTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIGZvclRhYmxlTmFtZTogZnVuY3Rpb24oKXtcbiAgICAgICAgICAgIHJldHVybiB0YmxOYW1lO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgY3VyclRhYmxlOiBmdW5jdGlvbigpe1xuICAgICAgICAgICAgcmV0dXJuICRzY29wZS50aGVUYWJsZU5hbWVcbiAgICAgICAgICB9LFxuICAgICAgICAgIGNvbE5hbWU6IGZ1bmN0aW9uICgpe1xuICAgICAgICAgICAgcmV0dXJuIGNvbDtcbiAgICAgICAgICB9LFxuICAgICAgICAgIGlkMTogZnVuY3Rpb24oKXtcbiAgICAgICAgICAgIHJldHVybiBpbmRleDtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH0pO1xuXG4gICAgICBtb2RhbEluc3RhbmNlLnJlc3VsdC50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgY29uc29sZS5sb2coXCJDTE9TRURcIilcbiAgICAgICAgJHNjb3BlLiRldmFsQXN5bmMoKTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICAkc2NvcGUudG9nZ2xlQW5pbWF0aW9uID0gZnVuY3Rpb24gKCkge1xuICAgICAgJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkID0gISRzY29wZS5hbmltYXRpb25zRW5hYmxlZDtcbiAgICB9O1xuXG4gICAgJHNjb3BlLmZpbHRlcmVkUm93cz1bXTtcbiAgICAkc2NvcGUuY3VycmVudFBhZ2U9MTtcbiAgICAkc2NvcGUubnVtUGVyUGFnZT0xMDtcbiAgICAkc2NvcGUubWF4U2l6ZT01O1xuXG4gICAgJHNjb3BlLiR3YXRjaChcImN1cnJlbnRQYWdlICsgbnVtUGVyUGFnZVwiLCBmdW5jdGlvbigpe1xuICAgICAgICB2YXIgYmVnaW4gPSAoKCRzY29wZS5jdXJyZW50UGFnZSAtIDEpICogJHNjb3BlLm51bVBlclBhZ2UpO1xuICAgICAgICB2YXIgZW5kID0gYmVnaW4gKyAkc2NvcGUubnVtUGVyUGFnZTtcbiAgICAgICAgJHNjb3BlLmZpbHRlcmVkUm93cyA9ICRzY29wZS5pbnN0YW5jZUFycmF5LnNsaWNlKGJlZ2luLCBlbmQpO1xuICAgIH0pXG5cbn0pO1xuIiwiYXBwLmNvbnRyb2xsZXIoJ1RhYmxlQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsIGFsbFRhYmxlcywgJHN0YXRlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgJHVpYk1vZGFsLCBIb21lRmFjdG9yeSwgYXNzb2NpYXRpb25zLCBhbGxDb2x1bW5zKSB7XG5cblx0JHNjb3BlLmFsbFRhYmxlcyA9IGFsbFRhYmxlcztcblxuXHQkc2NvcGUuY29sdW1uQXJyYXkgPSBbXTtcblxuXHQkc2NvcGUuZGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZVxuXG5cdCRzY29wZS5hc3NvY2lhdGlvbnMgPSBhc3NvY2lhdGlvbnM7XG5cblx0JHNjb3BlLmFsbENvbHVtbnMgPSBhbGxDb2x1bW5zO1xuXG5cdCRzY29wZS5hc3NvY2lhdGlvblRhYmxlID0gJHN0YXRlUGFyYW1zLmRiTmFtZSArICdfYXNzb2MnO1xuXG5cdCRzY29wZS5udW1UYWJsZXMgPSAkc2NvcGUuYWxsVGFibGVzLnJvd3MubGVuZ3RoO1xuXG5cdCRzY29wZS5hZGQgPSBmdW5jdGlvbigpIHtcblx0XHQkc2NvcGUuY29sdW1uQXJyYXkucHVzaCgnMScpO1xuXHR9XG5cblx0JHNjb3BlLiRzdGF0ZSA9ICRzdGF0ZTsgXHQvLyB1c2VkIHRvIGhpZGUgdGhlIGxpc3Qgb2YgYWxsIHRhYmxlcyB3aGVuIGluIHNpbmdsZSB0YWJsZSBzdGF0ZVxuXG5cdCRzY29wZS5hc3NvY2lhdGlvblR5cGVzID0gWydoYXNPbmUnLCAnaGFzTWFueSddO1xuXG5cdCRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lO1xuXG5cdCRzY29wZS5zdWJtaXR0ZWQgPSBmYWxzZTtcblxuXHQkc2NvcGUubWFrZUFzc29jaWF0aW9ucyA9IGZ1bmN0aW9uKGFzc29jaWF0aW9uLCBkYk5hbWUpIHtcblx0XHQkc2NvcGUuc3VibWl0dGVkID0gdHJ1ZTtcblx0XHRUYWJsZUZhY3RvcnkubWFrZUFzc29jaWF0aW9ucyhhc3NvY2lhdGlvbiwgZGJOYW1lKVxuXHRcdC8vIC50aGVuKGZ1bmN0aW9uKCkge1xuXHRcdC8vIFx0JHN0YXRlLmdvKCdUYWJsZScsIHtkYk5hbWUgOiAkc2NvcGUuZGJOYW1lfSwge3JlbG9hZDp0cnVlfSk7XG5cdFx0Ly8gfSlcblx0fSBcblxuXHQkc2NvcGUud2hlcmViZXR3ZWVuID0gZnVuY3Rpb24oY29uZGl0aW9uKSB7XG5cdFx0aWYoY29uZGl0aW9uID09PSBcIldIRVJFIEJFVFdFRU5cIiB8fCBjb25kaXRpb24gPT09IFwiV0hFUkUgTk9UIEJFVFdFRU5cIikgcmV0dXJuIHRydWU7XG5cdH1cblxuXHQkc2NvcGUuY3JlYXRlVGFibGUgPSBmdW5jdGlvbih0YWJsZSl7XG5cdFx0VGFibGVGYWN0b3J5LmNyZWF0ZVRhYmxlKHRhYmxlKVxuXHRcdC50aGVuKGZ1bmN0aW9uKCl7XG5cdFx0XHQkc3RhdGUuZ28oJ1RhYmxlJywge2RiTmFtZTogJHNjb3BlLmRiTmFtZX0sIHtyZWxvYWQ6IHRydWV9KTtcblx0XHR9KVxuXHR9XG5cblx0JHNjb3BlLmNvbHVtbkRhdGFUeXBlID0gZnVuY3Rpb24oKSB7XG5cdFx0JHNjb3BlLmFsbENvbHVtbnMuZm9yRWFjaChmdW5jdGlvbihvYmopIHtcblx0XHRcdGlmKG9iai50YWJsZV9uYW1lID09PSAkc2NvcGUucXVlcnkudGFibGUxICYmIG9iai5jb2x1bW5fbmFtZSA9PT0gJHNjb3BlLnF1ZXJ5LmNvbHVtbikgJHNjb3BlLnR5cGUgPSBvYmouZGF0YV90eXBlO1xuXHRcdH0pXG5cdH1cblxuXHQkc2NvcGUuc2VsZWN0ZWRBc3NvYyA9IHt9O1xuXG5cdC8vICRzY29wZS5nZXRBc3NvY2lhdGVkID0gZnVuY3Rpb24odGFibGVOYW1lKSB7XG5cdC8vIFx0JHNjb3BlLmFzc29jaWF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHJvdyl7XG5cdC8vIFx0XHRpZighJHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXSl7IFxuXHQvLyBcdFx0XHQkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdID0gW107XG5cdC8vIFx0XHR9XG5cdC8vIFx0XHRpZihyb3cuVGFibGUxID09PSB0YWJsZU5hbWUgJiYgJHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXS5pbmRleE9mKHJvdy5UYWJsZTIpID09IC0xKXtcblx0Ly8gXHRcdFx0JHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXS5wdXNoKHJvdy5UYWJsZTIpO1xuXHQvLyBcdFx0fVxuXHQvLyBcdFx0ZWxzZSBpZihyb3cuVGFibGUyID09PSB0YWJsZU5hbWUgJiYgJHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXS5pbmRleE9mKHJvdy5UYWJsZTEpID09IC0xKXtcblx0Ly8gXHRcdFx0JHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXS5wdXNoKHJvdy5UYWJsZTEpO1x0XG5cdC8vIFx0XHR9IFxuXHQvLyBcdH0pXG5cdC8vIH1cblxuXHQvLyAkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zID0gW107XG5cblx0Ly8gYXNzb2NpYXRpb25zLmZvckVhY2goZnVuY3Rpb24ocm93KXtcblx0Ly8gXHRpZihyb3cuVGFibGUxID09PSB0YWJsZU5hbWUgJiYgJHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXS5pbmRleE9mKHJvdy5UYWJsZTIpID09IC0xKXtcblx0Ly8gXHRcdCRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMucHVzaChyb3cuVGFibGUyKTtcblx0Ly8gXHR9XG5cdC8vIFx0ZWxzZSBpZihyb3cuVGFibGUyID09PSB0YWJsZU5hbWUgJiYgJHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXS5pbmRleE9mKHJvdy5UYWJsZTEpID09IC0xKXtcblx0Ly8gXHRcdCRzY29wZS5zZWxlY3RlZEFzc29jW3RhYmxlTmFtZV0ucHVzaChyb3cuVGFibGUxKTtcdFxuXHQvLyBcdH0gXG5cdC8vIH0pXG5cblx0JHNjb3BlLnN1Ym1pdFF1ZXJ5ID0gVGFibGVGYWN0b3J5LnN1Ym1pdFF1ZXJ5O1xuXG59KTtcbiIsImFwcC5mYWN0b3J5KCdUYWJsZUZhY3RvcnknLCBmdW5jdGlvbiAoJGh0dHAsICRzdGF0ZVBhcmFtcykge1xuXG5cdHZhciBUYWJsZUZhY3RvcnkgPSB7fTtcblxuXHRmdW5jdGlvbiByZXNUb0RhdGEocmVzKSB7XG4gICAgICAgIHJldHVybiByZXMuZGF0YTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZ2V0QWxsVGFibGVzID0gZnVuY3Rpb24oZGJOYW1lKXtcbiAgICBcdHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSlcbiAgICBcdC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZ2V0U2luZ2xlVGFibGUgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXREYk5hbWUgPSBmdW5jdGlvbihkYk5hbWUpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL21hc3RlcmRiLycgKyBkYk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZmlsdGVyID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIGRhdGEpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLnB1dCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lICsgJy9maWx0ZXInLCBkYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS51cGRhdGVCYWNrZW5kID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIGRhdGEpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLnB1dCgnYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUsIGRhdGEpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmFkZFJvdyA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCByb3dOdW1iZXIpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJ2FwaS9jbGllbnRkYi9hZGRyb3cvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSwge3Jvd051bWJlcjogcm93TnVtYmVyfSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkucmVtb3ZlUm93ID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIHJvd0lkLCBsZW5ndGgpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnLycgKyByb3dJZCArICcvJyArIGxlbmd0aClcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVDb2x1bW4gPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgY29sdW1uTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSArICcvY29sdW1uLycgKyBjb2x1bW5OYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmFkZENvbHVtbiA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCBudW1OZXdDb2wpe1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnYXBpL2NsaWVudGRiL2FkZGNvbHVtbi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lICsgJy8nICsgbnVtTmV3Q29sKVxuICAgIH1cbiAgICBUYWJsZUZhY3RvcnkuY3JlYXRlVGFibGUgPSBmdW5jdGlvbih0YWJsZSl7XG4gICAgICAgIHRhYmxlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG4gICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL2NsaWVudGRiJywgdGFibGUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmRlbGV0ZVRhYmxlID0gZnVuY3Rpb24oY3VycmVudFRhYmxlKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvY2xpZW50ZGIvJyArIGN1cnJlbnRUYWJsZS5kYk5hbWUgKyAnLycgKyBjdXJyZW50VGFibGUudGFibGVOYW1lKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5tYWtlQXNzb2NpYXRpb25zID0gZnVuY3Rpb24oYXNzb2NpYXRpb24sIGRiTmFtZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy9hc3NvY2lhdGlvbicsIGFzc29jaWF0aW9uKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5kZWxldGVEYiA9IGZ1bmN0aW9uKGRiTmFtZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldEFzc29jaWF0aW9ucyA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvYXNzb2NpYXRpb250YWJsZS8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgICBUYWJsZUZhY3RvcnkuZ2V0QWxsQXNzb2NpYXRpb25zID0gZnVuY3Rpb24oZGJOYW1lKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvYWxsYXNzb2NpYXRpb25zLycgKyBkYk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldEFsbENvbHVtbnMgPSBmdW5jdGlvbihkYk5hbWUpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi9nZXRhbGxjb2x1bW5zLycgKyBkYk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldENvbHVtbnNGb3JUYWJsZSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi9jb2x1bW5zZm9ydGFibGUvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkucnVuSm9pbiA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGUxLCBhcnJheU9mVGFibGVzLCBzZWxlY3RlZENvbHVtbnMsIGFzc29jaWF0aW9ucywgY29sc1RvUmV0dXJuKSB7XG4gICAgICAgIHZhciBkYXRhID0ge307XG4gICAgICAgIGRhdGEuZGJOYW1lID0gZGJOYW1lO1xuICAgICAgICBkYXRhLnRhYmxlMiA9IGFycmF5T2ZUYWJsZXNbMF07XG4gICAgICAgIGRhdGEuYXJyYXlPZlRhYmxlcyA9IGFycmF5T2ZUYWJsZXM7XG4gICAgICAgIGRhdGEuc2VsZWN0ZWRDb2x1bW5zID0gc2VsZWN0ZWRDb2x1bW5zO1xuICAgICAgICBkYXRhLmNvbHNUb1JldHVybiA9IGNvbHNUb1JldHVybjtcblxuICAgICAgICAvLyBbaGFzTWFueSwgaGFzT25lLCBoYXNNYW55IHByaW1hcnkga2V5LCBoYXNPbmUgZm9yZ2VpbiBrZXldXG5cbiAgICAgICAgYXNzb2NpYXRpb25zLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICBpZihyb3cuVGFibGUxID09PSB0YWJsZTEgJiYgcm93LlRhYmxlMiA9PT0gZGF0YS50YWJsZTIpe1xuICAgICAgICAgICAgICAgIGRhdGEuYWxpYXMgPSByb3cuQWxpYXMxO1xuICAgICAgICAgICAgICAgIGlmKHJvdy5SZWxhdGlvbnNoaXAxID09PSAnaGFzT25lJyl7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUxID0gcm93LlRhYmxlMjtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTIgPSByb3cuVGFibGUxO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNle1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMSA9IHJvdy5UYWJsZTE7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUyID0gcm93LlRhYmxlMjsgICBcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIGlmKHJvdy5UYWJsZTEgPT09IGRhdGEudGFibGUyICYmIHJvdy5UYWJsZTIgPT09IHRhYmxlMSl7XG4gICAgICAgICAgICAgICAgZGF0YS5hbGlhcyA9IHJvdy5BbGlhczE7XG4gICAgICAgICAgICAgICAgaWYocm93LlJlbGF0aW9uc2hpcDEgPT09ICdoYXNNYW55Jyl7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUxID0gcm93LlRhYmxlMTtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTIgPSByb3cuVGFibGUyO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNle1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMSA9IHJvdy5UYWJsZTI7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUyID0gcm93LlRhYmxlMTsgICBcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pXG5cbiAgICAgICAgcmV0dXJuICRodHRwLnB1dCgnL2FwaS9jbGllbnRkYi9ydW5qb2luJywgZGF0YSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZ2V0UHJpbWFyeUtleXMgPSBmdW5jdGlvbihpZCwgZGJOYW1lLCB0YWJsZU5hbWUsIGNvbHVtbmtleSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSArICcvJyArIGlkICsgXCIvXCIgKyBjb2x1bW5rZXkpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmZpbmRQcmltYXJ5ID0gZnVuY3Rpb24oZGJOYW1lLCB0YmxOYW1lKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi9wcmltYXJ5LycrZGJOYW1lKycvJyt0YmxOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5zZXRGb3JlaWduS2V5ID0gZnVuY3Rpb24oZGJOYW1lLCB0YmxOYW1lLCBjb2xOYW1lLCBpZDEsIGlkMil7XG4gICAgICAgIHZhciBkYXRhID0ge307XG4gICAgICAgIGRhdGEuZGJOYW1lID0gZGJOYW1lO1xuICAgICAgICBkYXRhLnRibE5hbWUgPSB0YmxOYW1lO1xuICAgICAgICBkYXRhLmNvbE5hbWUgPSBjb2xOYW1lO1xuICAgICAgICBkYXRhLmlkMSA9IGlkMTtcbiAgICAgICAgZGF0YS5pZDIgPSBpZDI7XG5cbiAgICAgICAgcmV0dXJuICRodHRwLnB1dCgnL2FwaS9jbGllbnRkYi9zZXRGb3JlaWduS2V5JywgZGF0YSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTsgICBcbiAgICB9XG5cblx0cmV0dXJuIFRhYmxlRmFjdG9yeTsgXG59KSIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlJywge1xuICAgICAgICB1cmw6ICcvOmRiTmFtZScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvdGFibGUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdUYWJsZUN0cmwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgIFx0YWxsVGFibGVzOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0QWxsVGFibGVzKCRzdGF0ZVBhcmFtcy5kYk5hbWUpO1xuICAgICAgICBcdH0sIFxuICAgICAgICAgICAgYXNzb2NpYXRpb25zOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0QWxsQXNzb2NpYXRpb25zKCRzdGF0ZVBhcmFtcy5kYk5hbWUpO1xuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIGFsbENvbHVtbnM6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRBbGxDb2x1bW5zKCRzdGF0ZVBhcmFtcy5kYk5hbWUpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSk7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUuU2luZ2xlJywge1xuICAgICAgICB1cmw6ICcvOnRhYmxlTmFtZScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvc2luZ2xldGFibGUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdTaW5nbGVUYWJsZUN0cmwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgICBzaW5nbGVUYWJsZTogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldFNpbmdsZVRhYmxlKCRzdGF0ZVBhcmFtcy5kYk5hbWUsICRzdGF0ZVBhcmFtcy50YWJsZU5hbWUpO1xuICAgICAgICAgICAgfSwgXG4gICAgICAgICAgICBhc3NvY2lhdGlvbnM6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRBc3NvY2lhdGlvbnMoJHN0YXRlUGFyYW1zLmRiTmFtZSwgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KTtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5Kb2luJywge1xuICAgICAgICB1cmw6ICcvOnRhYmxlTmFtZS86cm93SWQvOmtleS9qb2luJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9qb2luLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnSm9pblRhYmxlQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICAgIGpvaW5UYWJsZTogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldFByaW1hcnlLZXlzKCRzdGF0ZVBhcmFtcy5yb3dJZCwgJHN0YXRlUGFyYW1zLmRiTmFtZSwgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSwgJHN0YXRlUGFyYW1zLmtleSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KTtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5jcmVhdGUnLCB7XG4gICAgICAgIHVybDogJy9jcmVhdGV0YWJsZScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvY3JlYXRldGFibGUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdUYWJsZUN0cmwnXG4gICAgfSk7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUuc2V0QXNzb2NpYXRpb24nLCB7XG4gICAgICAgIHVybDogJy9zZXRhc3NvY2lhdGlvbicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvc2V0YXNzb2NpYXRpb24uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdUYWJsZUN0cmwnXG4gICAgfSk7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUuU2luZ2xlLnF1ZXJ5Jywge1xuICAgICAgICB1cmw6ICcvcXVlcnlyZXN1bHQnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL3F1ZXJ5Lmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUXVlcnlUYWJsZUN0cmwnXG4gICAgfSk7ICAgICBcblxufSk7IiwiYXBwLmZhY3RvcnkoJ0Z1bGxzdGFja1BpY3MnLCBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIFtcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CN2dCWHVsQ0FBQVhRY0UuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vZmJjZG4tc3Bob3Rvcy1jLWEuYWthbWFpaGQubmV0L2hwaG90b3MtYWsteGFwMS90MzEuMC04LzEwODYyNDUxXzEwMjA1NjIyOTkwMzU5MjQxXzgwMjcxNjg4NDMzMTI4NDExMzdfby5qcGcnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0ItTEtVc2hJZ0FFeTlTSy5qcGcnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I3OS1YN29DTUFBa3c3eS5qcGcnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0ItVWo5Q09JSUFJRkFoMC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I2eUl5RmlDRUFBcWwxMi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFLVQ3NWxXQUFBbXFxSi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFdlpBZy1WQUFBazkzMi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFZ05NZU9YSUFJZkRoSy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFUXlJRE5XZ0FBdTYwQi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NDRjNUNVFXOEFFMmxHSi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NBZVZ3NVNXb0FBQUxzai5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NBYUpJUDdVa0FBbElHcy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NBUU93OWxXRUFBWTlGbC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0ItT1FiVnJDTUFBTndJTS5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I5Yl9lcndDWUFBd1JjSi5wbmc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I1UFRkdm5DY0FFQWw0eC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I0cXdDMGlDWUFBbFBHaC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0IyYjMzdlJJVUFBOW8xRC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0J3cEl3cjFJVUFBdk8yXy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0JzU3NlQU5DWUFFT2hMdy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NKNHZMZnVVd0FBZGE0TC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NJN3d6akVWRUFBT1BwUy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NJZEh2VDJVc0FBbm5IVi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NHQ2lQX1lXWUFBbzc1Vi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NJUzRKUElXSUFJMzdxdS5qcGc6bGFyZ2UnXG4gICAgXTtcbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ1JhbmRvbUdyZWV0aW5ncycsIGZ1bmN0aW9uICgpIHtcblxuICAgIHZhciBnZXRSYW5kb21Gcm9tQXJyYXkgPSBmdW5jdGlvbiAoYXJyKSB7XG4gICAgICAgIHJldHVybiBhcnJbTWF0aC5mbG9vcihNYXRoLnJhbmRvbSgpICogYXJyLmxlbmd0aCldO1xuICAgIH07XG5cbiAgICB2YXIgZ3JlZXRpbmdzID0gW1xuICAgICAgICAnSGVsbG8sIHdvcmxkIScsXG4gICAgICAgICdBdCBsb25nIGxhc3QsIEkgbGl2ZSEnLFxuICAgICAgICAnSGVsbG8sIHNpbXBsZSBodW1hbi4nLFxuICAgICAgICAnV2hhdCBhIGJlYXV0aWZ1bCBkYXkhJyxcbiAgICAgICAgJ0lcXCdtIGxpa2UgYW55IG90aGVyIHByb2plY3QsIGV4Y2VwdCB0aGF0IEkgYW0geW91cnMuIDopJyxcbiAgICAgICAgJ1RoaXMgZW1wdHkgc3RyaW5nIGlzIGZvciBMaW5kc2F5IExldmluZS4nLFxuICAgICAgICAn44GT44KT44Gr44Gh44Gv44CB44Om44O844K244O85qeY44CCJyxcbiAgICAgICAgJ1dlbGNvbWUuIFRvLiBXRUJTSVRFLicsXG4gICAgICAgICc6RCcsXG4gICAgICAgICdZZXMsIEkgdGhpbmsgd2VcXCd2ZSBtZXQgYmVmb3JlLicsXG4gICAgICAgICdHaW1tZSAzIG1pbnMuLi4gSSBqdXN0IGdyYWJiZWQgdGhpcyByZWFsbHkgZG9wZSBmcml0dGF0YScsXG4gICAgICAgICdJZiBDb29wZXIgY291bGQgb2ZmZXIgb25seSBvbmUgcGllY2Ugb2YgYWR2aWNlLCBpdCB3b3VsZCBiZSB0byBuZXZTUVVJUlJFTCEnLFxuICAgIF07XG5cbiAgICByZXR1cm4ge1xuICAgICAgICBncmVldGluZ3M6IGdyZWV0aW5ncyxcbiAgICAgICAgZ2V0UmFuZG9tR3JlZXRpbmc6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiBnZXRSYW5kb21Gcm9tQXJyYXkoZ3JlZXRpbmdzKTtcbiAgICAgICAgfVxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZSgnZnVsbHN0YWNrTG9nbycsIGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4ge1xuICAgICAgICByZXN0cmljdDogJ0UnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL2Z1bGxzdGFjay1sb2dvL2Z1bGxzdGFjay1sb2dvLmh0bWwnXG4gICAgfTtcbn0pOyIsImFwcC5kaXJlY3RpdmUoJ3NpZGViYXInLCBmdW5jdGlvbiAoJHJvb3RTY29wZSwgQXV0aFNlcnZpY2UsIEFVVEhfRVZFTlRTLCAkc3RhdGUpIHtcblxuICAgIHJldHVybiB7XG4gICAgICAgIHJlc3RyaWN0OiAnRScsXG4gICAgICAgIHNjb3BlOiB7fSxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9uYXZiYXIvbmF2YmFyLmh0bWwnLFxuICAgICAgICBsaW5rOiBmdW5jdGlvbiAoc2NvcGUpIHtcblxuICAgICAgICAgICAgc2NvcGUuaXRlbXMgPSBbXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ0hvbWUnLCBzdGF0ZTogJ2hvbWUnIH0sXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ0Fib3V0Jywgc3RhdGU6ICdhYm91dCcgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnRG9jdW1lbnRhdGlvbicsIHN0YXRlOiAnZG9jcycgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnTWVtYmVycyBPbmx5Jywgc3RhdGU6ICdtZW1iZXJzT25seScsIGF1dGg6IHRydWUgfVxuICAgICAgICAgICAgXTtcblxuICAgICAgICAgICAgc2NvcGUudXNlciA9IG51bGw7XG5cbiAgICAgICAgICAgIHNjb3BlLmlzTG9nZ2VkSW4gPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgc2NvcGUubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIEF1dGhTZXJ2aWNlLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnbGFuZGluZ1BhZ2UnKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHZhciBzZXRVc2VyID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpLnRoZW4oZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgICAgICAgICAgICAgc2NvcGUudXNlciA9IHVzZXI7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICB2YXIgcmVtb3ZlVXNlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBzY29wZS51c2VyID0gbnVsbDtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHNldFVzZXIoKTtcblxuICAgICAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMubG9naW5TdWNjZXNzLCBzZXRVc2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLmxvZ291dFN1Y2Nlc3MsIHJlbW92ZVVzZXIpO1xuICAgICAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsIHJlbW92ZVVzZXIpO1xuXG4gICAgICAgIH1cblxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZSgncmFuZG9HcmVldGluZycsIGZ1bmN0aW9uIChSYW5kb21HcmVldGluZ3MpIHtcblxuICAgIHJldHVybiB7XG4gICAgICAgIHJlc3RyaWN0OiAnRScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvY29tbW9uL2RpcmVjdGl2ZXMvcmFuZG8tZ3JlZXRpbmcvcmFuZG8tZ3JlZXRpbmcuaHRtbCcsXG4gICAgICAgIGxpbms6IGZ1bmN0aW9uIChzY29wZSkge1xuICAgICAgICAgICAgc2NvcGUuZ3JlZXRpbmcgPSBSYW5kb21HcmVldGluZ3MuZ2V0UmFuZG9tR3JlZXRpbmcoKTtcbiAgICAgICAgfVxuICAgIH07XG5cbn0pOyJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
