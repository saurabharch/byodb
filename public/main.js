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
app.controller('SingleTableCtrl', function ($scope, TableFactory, $stateParams, singleTable, $window, $state, $uibModal, associations) {

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

    $scope.makeAssociations = function (association, dbName) {
        TableFactory.makeAssociations(association, dbName).then(function () {
            $state.go('Table', { dbName: $scope.dbName }, { reload: true });
        });
    };

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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcC5qcyIsImFib3V0L2Fib3V0LmpzIiwiY3JlYXRlREIvY3JlYXRlREIuY29udHJvbGxlci5qcyIsImNyZWF0ZURCL2NyZWF0ZURCLmZhY3RvcnkuanMiLCJjcmVhdGVEQi9jcmVhdGVEQi5zdGF0ZS5qcyIsImRvY3MvZG9jcy5qcyIsImZzYS9mc2EtcHJlLWJ1aWx0LmpzIiwiaG9tZS9ob21lLmNvbnRyb2xsZXIuanMiLCJob21lL2hvbWUuZmFjdG9yeS5qcyIsImhvbWUvaG9tZS5zdGF0ZS5qcyIsImxhbmRpbmdQYWdlL2xhbmRpbmdQYWdlLnN0YXRlLmpzIiwibG9naW4vbG9naW4uanMiLCJtZW1iZXJzLW9ubHkvbWVtYmVycy1vbmx5LmpzIiwib2F1dGgvb2F1dGgtYnV0dG9uLmRpcmVjdGl2ZS5qcyIsInNpZ251cC9zaWdudXAuanMiLCJ0YWJsZS9kZWxldGVEQk1vZGFsLmpzIiwidGFibGUvZGVsZXRlVGFibGVNb2RhbC5qcyIsInRhYmxlL2pvaW4uY29udHJvbGxlci5qcyIsInRhYmxlL3F1ZXJ5LmNvbnRyb2xsZXIuanMiLCJ0YWJsZS9zaW5nbGV0YWJsZS5jb250cm9sbGVyLmpzIiwidGFibGUvdGFibGUuY29udHJvbGxlci5qcyIsInRhYmxlL3RhYmxlLmZhY3RvcnkuanMiLCJ0YWJsZS90YWJsZS5zdGF0ZS5qcyIsImNvbW1vbi9mYWN0b3JpZXMvRnVsbHN0YWNrUGljcy5qcyIsImNvbW1vbi9mYWN0b3JpZXMvUmFuZG9tR3JlZXRpbmdzLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvZnVsbHN0YWNrLWxvZ28vZnVsbHN0YWNrLWxvZ28uanMiLCJjb21tb24vZGlyZWN0aXZlcy9uYXZiYXIvbmF2YmFyLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvcmFuZG8tZ3JlZXRpbmcvcmFuZG8tZ3JlZXRpbmcuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7O0FBQ0EsT0FBQSxHQUFBLEdBQUEsUUFBQSxNQUFBLENBQUEsdUJBQUEsRUFBQSxDQUFBLGFBQUEsRUFBQSxXQUFBLEVBQUEsY0FBQSxFQUFBLFdBQUEsQ0FBQSxDQUFBOztBQUVBLElBQUEsTUFBQSxDQUFBLFVBQUEsa0JBQUEsRUFBQSxpQkFBQSxFQUFBOztBQUVBLHNCQUFBLFNBQUEsQ0FBQSxJQUFBOztBQUVBLHVCQUFBLFNBQUEsQ0FBQSxHQUFBOztBQUVBLHVCQUFBLElBQUEsQ0FBQSxpQkFBQSxFQUFBLFlBQUE7QUFDQSxlQUFBLFFBQUEsQ0FBQSxNQUFBO0FBQ0EsS0FGQTtBQUdBLENBVEE7OztBQVlBLElBQUEsR0FBQSxDQUFBLFVBQUEsVUFBQSxFQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7OztBQUdBLFFBQUEsK0JBQUEsU0FBQSw0QkFBQSxDQUFBLEtBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxJQUFBLElBQUEsTUFBQSxJQUFBLENBQUEsWUFBQTtBQUNBLEtBRkE7Ozs7QUFNQSxlQUFBLEdBQUEsQ0FBQSxtQkFBQSxFQUFBLFVBQUEsS0FBQSxFQUFBLE9BQUEsRUFBQSxRQUFBLEVBQUE7O0FBRUEsWUFBQSxDQUFBLDZCQUFBLE9BQUEsQ0FBQSxFQUFBOzs7QUFHQTtBQUNBOztBQUVBLFlBQUEsWUFBQSxlQUFBLEVBQUEsRUFBQTs7O0FBR0E7QUFDQTs7O0FBR0EsY0FBQSxjQUFBOztBQUVBLG9CQUFBLGVBQUEsR0FBQSxJQUFBLENBQUEsVUFBQSxJQUFBLEVBQUE7Ozs7QUFJQSxnQkFBQSxJQUFBLEVBQUE7QUFDQSx1QkFBQSxFQUFBLENBQUEsUUFBQSxJQUFBLEVBQUEsUUFBQTtBQUNBLGFBRkEsTUFFQTtBQUNBLHVCQUFBLEVBQUEsQ0FBQSxPQUFBO0FBQ0E7QUFDQSxTQVRBO0FBV0EsS0E1QkE7QUE4QkEsQ0F2Q0E7O0FDZkEsSUFBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7OztBQUdBLG1CQUFBLEtBQUEsQ0FBQSxPQUFBLEVBQUE7QUFDQSxhQUFBLFFBREE7QUFFQSxvQkFBQSxpQkFGQTtBQUdBLHFCQUFBO0FBSEEsS0FBQTtBQU1BLENBVEE7O0FBV0EsSUFBQSxVQUFBLENBQUEsaUJBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxhQUFBLEVBQUE7OztBQUdBLFdBQUEsTUFBQSxHQUFBLEVBQUEsT0FBQSxDQUFBLGFBQUEsQ0FBQTtBQUVBLENBTEE7QUNYQSxJQUFBLFVBQUEsQ0FBQSxjQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBLGVBQUEsRUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxLQUFBO0FBQ0EsV0FBQSxXQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLEdBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxXQUFBLENBQUEsSUFBQSxDQUFBLEdBQUE7QUFDQSxLQUZBOztBQUlBLFdBQUEsUUFBQSxHQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0Esd0JBQUEsUUFBQSxDQUFBLElBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxJQUFBLEVBQUE7QUFDQSxtQkFBQSxTQUFBLEdBQUEsSUFBQTtBQUNBLFNBSEE7QUFJQSxLQUxBOztBQU9BLFdBQUEsV0FBQSxHQUFBLFVBQUEsS0FBQSxFQUFBLEVBQUEsRUFBQTtBQUNBLHdCQUFBLFdBQUEsQ0FBQSxLQUFBLEVBQUEsRUFBQTtBQUNBLGVBQUEsRUFBQSxDQUFBLE9BQUEsRUFBQSxFQUFBLFFBQUEsT0FBQSxTQUFBLENBQUEsTUFBQSxFQUFBLEVBQUEsRUFBQSxRQUFBLElBQUEsRUFBQTtBQUNBLEtBSEE7QUFJQSxDQXBCQTs7QUNBQSxJQUFBLE9BQUEsQ0FBQSxpQkFBQSxFQUFBLFVBQUEsS0FBQSxFQUFBOztBQUVBLFFBQUEsa0JBQUEsRUFBQTs7QUFFQSxhQUFBLFNBQUEsQ0FBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLElBQUEsSUFBQTtBQUNBOztBQUVBLG9CQUFBLFFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxJQUFBLENBQUEsZUFBQSxFQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxvQkFBQSxXQUFBLEdBQUEsVUFBQSxLQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsY0FBQSxNQUFBLEdBQUEsVUFBQSxNQUFBO0FBQ0EsZUFBQSxNQUFBLElBQUEsQ0FBQSxlQUFBLEVBQUEsS0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUpBOztBQU1BLFdBQUEsZUFBQTtBQUNBLENBcEJBOztBQ0FBLElBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0EsbUJBQUEsS0FBQSxDQUFBLFVBQUEsRUFBQTtBQUNBLGFBQUEsV0FEQTtBQUVBLHFCQUFBLDJCQUZBO0FBR0Esb0JBQUEsY0FIQTtBQUlBLGlCQUFBO0FBQ0EsMEJBQUEsc0JBQUEsV0FBQSxFQUFBO0FBQ0EsdUJBQUEsWUFBQSxlQUFBLEVBQUE7QUFDQTtBQUhBO0FBSkEsS0FBQTtBQVdBLENBWkE7QUNBQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLG1CQUFBLEtBQUEsQ0FBQSxNQUFBLEVBQUE7QUFDQSxhQUFBLE9BREE7QUFFQSxxQkFBQTtBQUZBLEtBQUE7QUFJQSxDQUxBOztBQ0FBLENBQUEsWUFBQTs7QUFFQTs7OztBQUdBLFFBQUEsQ0FBQSxPQUFBLE9BQUEsRUFBQSxNQUFBLElBQUEsS0FBQSxDQUFBLHdCQUFBLENBQUE7O0FBRUEsUUFBQSxNQUFBLFFBQUEsTUFBQSxDQUFBLGFBQUEsRUFBQSxFQUFBLENBQUE7O0FBRUEsUUFBQSxPQUFBLENBQUEsUUFBQSxFQUFBLFlBQUE7QUFDQSxZQUFBLENBQUEsT0FBQSxFQUFBLEVBQUEsTUFBQSxJQUFBLEtBQUEsQ0FBQSxzQkFBQSxDQUFBO0FBQ0EsZUFBQSxPQUFBLEVBQUEsQ0FBQSxPQUFBLFFBQUEsQ0FBQSxNQUFBLENBQUE7QUFDQSxLQUhBOzs7OztBQVFBLFFBQUEsUUFBQSxDQUFBLGFBQUEsRUFBQTtBQUNBLHNCQUFBLG9CQURBO0FBRUEscUJBQUEsbUJBRkE7QUFHQSx1QkFBQSxxQkFIQTtBQUlBLHdCQUFBLHNCQUpBO0FBS0EsMEJBQUEsd0JBTEE7QUFNQSx1QkFBQTtBQU5BLEtBQUE7O0FBU0Es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QSxTQUZBOztBQUlBLGFBQUEsRUFBQSxHQUFBLElBQUE7QUFDQSxhQUFBLElBQUEsR0FBQSxJQUFBOztBQUVBLGFBQUEsTUFBQSxHQUFBLFVBQUEsU0FBQSxFQUFBLElBQUEsRUFBQTtBQUNBLGlCQUFBLEVBQUEsR0FBQSxTQUFBO0FBQ0EsaUJBQUEsSUFBQSxHQUFBLElBQUE7QUFDQSxTQUhBOztBQUtBLGFBQUEsT0FBQSxHQUFBLFlBQUE7QUFDQSxpQkFBQSxFQUFBLEdBQUEsSUFBQTtBQUNBLGlCQUFBLElBQUEsR0FBQSxJQUFBO0FBQ0EsU0FIQTtBQUtBLEtBekJBO0FBMkJBLENBNUlBOztBQ0FBLElBQUEsVUFBQSxDQUFBLFVBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBOztBQUVBLFdBQUEsTUFBQSxHQUFBLE1BQUE7QUFDQSxDQUhBOztBQ0FBLElBQUEsT0FBQSxDQUFBLGFBQUEsRUFBQSxVQUFBLEtBQUEsRUFBQTs7QUFFQSxRQUFBLGNBQUEsRUFBQTs7QUFFQSxhQUFBLFNBQUEsQ0FBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLElBQUEsSUFBQTtBQUNBOztBQUVBLGdCQUFBLFNBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxlQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsZ0JBQUEsUUFBQSxHQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLE1BQUEsQ0FBQSxtQkFBQSxJQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsV0FBQSxXQUFBO0FBQ0EsQ0FuQkE7QUNBQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLG1CQUFBLEtBQUEsQ0FBQSxNQUFBLEVBQUE7QUFDQSxhQUFBLE9BREE7QUFFQSxxQkFBQSxtQkFGQTtBQUdBLG9CQUFBLFVBSEE7QUFJQSxpQkFBQTtBQUNBLG9CQUFBLGdCQUFBLFdBQUEsRUFBQTtBQUNBLHVCQUFBLFlBQUEsU0FB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V0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBOztBQUVBLFdBQUEsWUFBQSxHQUFBLGVBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsWUFBQTtBQUNBLHFCQUFBLFFBQUEsQ0FBQSxPQUFBLE1BQUE7O0FBRUEsS0FIQTs7QUFLQSxXQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsMEJBQUEsT0FBQSxDQUFBLFFBQUE7QUFDQSxLQUZBO0FBR0EsQ0FkQTtBQzVCQSxJQUFBLFVBQUEsQ0FBQSxlQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQSxTQUFBLEVBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsU0FBQTs7QUFHQSxhQUFBLGFBQUEsR0FBQTtBQUNBLGVBQUEsT0FBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLFFBQUEsT0FBQSxTQUFBLENBQUEsQ0FBQSxDQUFBOztBQUdBLGFBQUEsSUFBQSxJQUFBLElBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxPQUFBLENBQUEsSUFBQSxDQUFBLElBQUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7OztBQUlBLGFBQUEsVUFBQSxHQUFBO0FBQ0EsWUFBQSxLQUFBO0FBQ0EsZUFBQSxhQUFBLEdBQUEsRUFBQTtBQUNBLGtCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLFlBQUEsRUFBQTtBQUNBLGlCQUFBLElBQUEsSUFBQSxJQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBLFVBQUEsSUFBQSxDQUFBLElBQUEsSUFBQSxDQUFBO0FBQ0E7QUFDQSxtQkFBQSxhQUFBLENBQUEsSUFBQSxDQUFBLFNBQUE7QUFDQSxTQU5BO0FBT0E7OztBQUdBO0FBR0EsQ0FyQ0E7QUNBQSxJQUFBLFVBQUEsQ0FBQSxnQkFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUE7O0FBR0EsYUFBQSxhQUFBLEdBQUE7QUFDQSxlQUFBLE9BQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxRQUFBLE9BQUEsU0FBQSxDQUFBLENBQUEsQ0FBQTs7QUFHQSxhQUFBLElBQUEsSUFBQSxJQUFBLEtBQUEsRUFBQTtBQUNBLGdCQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxJQUFBO0FBQ0E7QUFDQTtBQUNBOztBQUVBOzs7QUFJQSxhQUFBLFVBQUEsR0FBQTtBQUNBLFlBQUEsS0FBQTtBQUNBLGVBQUEsYUFBQSxHQUFBLEVBQUE7QUFDQSxrQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxZQUFBLEVBQUE7QUFDQSxpQkFBQSxJQUFBLElBQUEsSUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxTQUFBLFlBQUEsSUFBQSxTQUFBLFlBQUEsRUFBQSxVQUFBLElBQUEsQ0FBQSxJQUFBLElBQUEsQ0FBQTtBQUNBO0FBQ0EsbUJBQUEsYUFBQSxDQUFBLElBQUEsQ0FBQSxTQUFBO0FBQ0EsU0FOQTtBQU9BOzs7QUFHQTtBQUdBLENBbkNBO0FDQUEsSUFBQSxVQUFBLENBQUEsaUJBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBLFdBQUEsRUFBQSxPQUFBLEVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxZQUFBLEVBQUE7Ozs7QUFJQSxXQUFBLFNBQUEsR0FBQSxhQUFBLE1BQUE7QUFDQSxXQUFBLFlBQUEsR0FBQSxhQUFBLFNBQUE7QUFDQSxXQUFBLFdBQUEsR0FBQSxZQUFBLENBQUEsQ0FBQTtBQUNBLFdBQUEsV0FBQSxHQUFBLEtBQUE7QUFDQSxXQUFBLFlBQUEsR0FBQSxZQUFBOztBQUlBLGFBQUEsZ0JBQUEsR0FBQTtBQUNBLFlBQUEsY0FBQSxFQUFBO0FBQ0EsZUFBQSxZQUFBLENBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxNQUFBLEtBQUEsT0FBQSxZQUFBLElBQUEsSUFBQSxhQUFBLEtBQUEsUUFBQSxFQUFBO0FBQ0EsNEJBQUEsSUFBQSxNQUFBLElBQUEsSUFBQSxNQUFBO0FBQ0EsYUFGQSxNQUVBLElBQUEsSUFBQSxNQUFBLEtBQUEsT0FBQSxZQUFBLElBQUEsSUFBQSxhQUFBLEtBQUEsUUFBQSxFQUFBO0FBQ0EsNEJBQUEsSUFBQSxNQUFBLElBQUEsSUFBQSxNQUFBO0FBQ0E7QUFDQSxTQU5BO0FBT0EsZUFBQSxXQUFBLEdBQUEsV0FBQTtBQUNBOztBQUVBOztBQUdBLFdBQUEsWUFBQSxHQUFBLFlBQUE7O0FBRUEsV0FBQSxPQUFBLEdBQUEsQ0FBQTs7QUFFQSxXQUFBLEdBQUEsR0FBQSxPQUFBLFdBQUEsQ0FBQSxHQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLElBQUEsRUFBQTtBQUNBLEtBRkEsQ0FBQTs7O0FBS0EsV0FBQSxVQUFBLEdBQUEsS0FBQTtBQUNBLFdBQUEsWUFBQSxHQUFBLFlBQUE7QUFDQSxlQUFBLFVBQUEsR0FBQSxDQUFBLE9BQUEsVUFBQTtBQUNBLEtBRkE7O0FBSUEsV0FBQSxjQUFBLEdBQUEsVUFBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLGFBQUEsRUFBQTtBQUNBLHNCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLElBQUEsUUFBQSxFQUFBO0FBQ0EsNkJBQUEsU0FBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsSUFBQSxRQUFBLEVBQUEsQ0FBQSxFQUFBLE9BQUEsQ0FBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE1BQUEsRUFBQTtBQUNBLDJCQUFBLFdBQUEsR0FBQSxNQUFBO0FBQ0E7QUFDQSxpQkFKQTtBQUtBO0FBQ0EsU0FSQTtBQVNBLGVBQUEsVUFBQSxHQUFBLEtBQUE7QUFDQSxLQVhBOztBQWFBLFdBQUEsU0FBQSxHQUFBLFVBQUEsYUFBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLFdBQUEsRUFBQTtBQUNBLDBCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFFBQUEsR0FBQSxJQUFBO0FBQ0EsYUFGQTtBQUdBLFNBSkEsTUFJQTtBQUNBLDBCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFFBQUEsR0FBQSxLQUFBO0FBQ0EsYUFGQTtBQUdBO0FBQ0EsS0FWQTs7QUFZQSxXQUFBLGdCQUFBLEdBQUEsVUFBQSxhQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsV0FBQSxLQUFBLElBQUEsRUFBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxLQUFBO0FBQ0E7QUFDQSxLQUpBOztBQU1BLFdBQUEsU0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxxQkFBQSxTQUFBLENBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxHQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsbUJBQUEsV0FBQSxHQUFBLE1BQUE7QUFDQTtBQUNBLFNBSkE7QUFLQSxLQU5BOztBQVFBLFdBQUEsWUFBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxVQUFBLEVBQUE7QUFDQSxxQkFBQSxZQUFBLENBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxVQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsbUJBQUEsV0FBQSxHQUFBLE1BQUE7QUFDQTtBQUNBO0FBQ0EsU0FMQTtBQU1BLEtBUEE7O0FBU0EsV0FBQSxNQUFBLEdBQUEsVUFBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsU0FBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLENBQUEsVUFBQSxPQUFBLEVBQUE7QUFDQSxtQkFBQSxJQUFBLENBQUEsUUFBQSxNQUFBLENBQUEsQ0FBQSxFQUFBLEtBQUE7QUFDQSxTQUZBO0FBR0EsWUFBQSxTQUFBLE9BQUEsSUFBQSxDQUFBLFVBQUEsQ0FBQSxFQUFBLENBQUEsRUFBQTtBQUNBLG1CQUFBLElBQUEsQ0FBQTtBQUNBLFNBRkEsQ0FBQTtBQUdBLFlBQUEsT0FBQSxNQUFBLEdBQUEsQ0FBQSxFQUFBO0FBQ0EseUJBQUEsTUFBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE1BQUEsRUFBQTtBQUNBLHVCQUFBLFdBQUEsR0FBQSxNQUFBO0FBQ0E7QUFDQSxhQUpBO0FBTUEsU0FQQSxNQU9BO0FBQ0EseUJBQUEsTUFBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsQ0FBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE1BQUEsRUFBQTtBQUNBLHVCQUFBLFdBQUEsR0FBQSxNQUFBO0FBQ0E7QUFDQSxhQUpBO0FBS0E7QUFDQSxLQXRCQTs7QUF3QkEsV0FBQSxTQUFBLEdBQUEsVUFBQSxFQUFBLEVBQUEsS0FBQSxFQUFBO0FBQ0EsWUFBQSxVQUFBLE9BQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxHQUFBLEVBQUEsS0FBQSxDQUFBLE1BQUEsQ0FBQTtBQUNBLFlBQUEsT0FBQSxFQUFBO0FBQ0EsZ0JBQUEsYUFBQSxRQUFBLElBQUEsQ0FBQSxVQUFBLENBQUEsRUFBQSxDQUFBLEVBQUE7QUFDQSx1QkFBQSxJQUFBLENBQUE7QUFDQSxhQUZBLENBQUE7QUFHQSxnQkFBQSxXQUFBLE9BQUEsV0FBQSxDQUFBLENBQUEsSUFBQSxDQUFBO0FBQ0EsZ0JBQUEsYUFBQSxZQUFBLFNBQUEsUUFBQSxFQUFBOztBQUVBLHlCQUFBLFNBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLFVBQUEsRUFDQSxJQURBLENBQ0EsWUFBQTtBQUNBLHVCQUFBLGFBQUEsY0FBQSxDQUFBLGFBQUEsTUFBQSxFQUFBLGFBQUEsU0FBQSxDQUFBO0FBQ0EsYUFIQSxFQUlBLElBSkEsQ0FJQSxVQUFBLFFBQUEsRUFBQTtBQUNBLHVCQUFBLFdBQUEsR0FBQSxTQUFBLENBQUEsQ0FBQTtBQUNBO0FBQ0E7QUFDQSxhQVJBO0FBU0EsU0FoQkEsTUFnQkE7QUFDQSxnQkFBQSxhQUFBLE9BQUEsT0FBQSxDQUFBLE1BQUEsR0FBQSxDQUFBO0FBQ0EsZ0JBQUEsYUFBQSxZQUFBLFVBQUE7QUFDQSx5QkFBQSxTQUFBLENBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxVQUFBLEVBQ0EsSUFEQSxDQUNBLFlBQUE7QUFDQSx1QkFBQSxhQUFBLGNBQUEsQ0FBQSxhQUFBLE1BQUEsRUFBQSxhQUFBLFNBQUEsQ0FBQTtBQUNBLGFBSEEsRUFJQSxJQUpBLENBSUEsVUFBQSxRQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLEdBQUEsU0FBQSxDQUFBLENBQUE7QUFDQTtBQUNBO0FBQ0EsYUFSQTtBQVNBO0FBRUEsS0FoQ0E7Ozs7OztBQXNDQSxhQUFBLGFBQUEsR0FBQTtBQUNBLGVBQUEsT0FBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLGVBQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxRQUFBLE9BQUEsV0FBQSxDQUFBLENBQUEsQ0FBQTs7QUFHQSxhQUFBLElBQUEsSUFBQSxJQUFBLEtBQUEsRUFBQTtBQUNBLGdCQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxJQUFBO0FBQ0EsdUJBQUEsZUFBQSxDQUFBLElBQUEsQ0FBQSxJQUFBO0FBQ0E7QUFDQTtBQUNBOztBQUVBOztBQUVBLGFBQUEsb0JBQUEsR0FBQTtBQUNBLFlBQUEsT0FBQSxZQUFBLENBQUEsTUFBQSxHQUFBLENBQUEsRUFBQTtBQUNBLG1CQUFBLGNBQUEsR0FBQSxFQUFBO0FBQ0EsbUJBQUEsWUFBQSxDQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLElBQUEsTUFBQSxLQUFBLE9BQUEsWUFBQSxJQUFBLElBQUEsYUFBQSxLQUFBLFNBQUEsRUFBQTtBQUNBLHdCQUFBLFVBQUEsRUFBQTtBQUNBLDRCQUFBLElBQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSx3QkFBQSxJQUFBLE9BQUEsRUFBQTtBQUNBLGdDQUFBLEtBQUEsR0FBQSxJQUFBLE9BQUE7QUFDQSxnQ0FBQSxTQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EscUJBSEEsTUFHQTtBQUNBLGdDQUFBLEtBQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSxnQ0FBQSxTQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0E7QUFDQSwyQkFBQSxjQUFBLENBQUEsSUFBQSxDQUFBLE9BQUE7QUFDQSxpQkFYQSxNQVdBLElBQUEsSUFBQSxNQUFBLEtBQUEsT0FBQSxZQUFBLElBQUEsSUFBQSxhQUFBLEtBQUEsU0FBQSxFQUFBO0FBQ0Esd0JBQUEsVUFBQSxFQUFBO0FBQ0EsNEJBQUEsSUFBQSxHQUFBLElBQUEsTUFBQTtBQUNBLHdCQUFBLElBQUEsT0FBQSxFQUFBO0FBQ0EsZ0NBQUEsS0FBQSxHQUFBLElBQUEsT0FBQTtBQUNBLGdDQUFBLFNBQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSxxQkFIQSxNQUdBO0FBQ0EsZ0NBQUEsS0FBQSxHQUFBLElBQUEsTUFBQTtBQUNBLGdDQUFBLFNBQUEsR0FBQSxJQUFBLE1BQUE7QUFDQTtBQUNBLDJCQUFBLGNBQUEsQ0FBQSxJQUFBLENBQUEsT0FBQTtBQUNBO0FBQ0EsYUF4QkE7QUF5QkE7QUFDQTs7QUFFQTs7O0FBR0EsYUFBQSxVQUFBLEdBQUE7QUFDQSxlQUFBLGFBQUEsR0FBQSxFQUFBO0FBQ0EsZUFBQSxXQUFBLENBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsWUFBQSxFQUFBO0FBQ0EsZ0JBQUEsU0FBQSxFQUFBOztBQUVBLGlCQUFBLElBQUEsSUFBQSxJQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBLFVBQUEsSUFBQSxDQUFBO0FBQ0EseUJBQUEsSUFEQTtBQUVBLDJCQUFBLElBQUEsSUFBQTtBQUZBLGlCQUFBO0FBSUE7QUFDQSxtQkFBQSxNQUFBLEdBQUEsU0FBQTtBQUNBLG1CQUFBLGFBQUEsQ0FBQSxJQUFBLENBQUEsTUFBQTtBQUNBLFNBWkE7QUFhQTs7O0FBR0E7O0FBRUEsV0FBQSxNQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLElBQUEsRUFBQTtBQUNBLHFCQUFBLE1BQUEsQ0FBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLElBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSxtQkFBQSxXQUFBLEdBQUEsT0FBQSxJQUFBO0FBQ0E7QUFDQSxTQUpBO0FBS0EsS0FOQTs7QUFTQSxXQUFBLFlBQUEsR0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGVBQUEsT0FBQSxXQUFBLENBQUEsY0FBQSxDQUFBLEdBQUEsQ0FBQTtBQUNBLEtBRkE7O0FBSUEsV0FBQSxXQUFBLEdBQUEsYUFBQSxXQUFBOzs7Ozs7OztBQVNBLFdBQUEsZUFBQSxHQUFBLEVBQUE7O0FBRUEsV0FBQSxhQUFBLEdBQUEsVUFBQSxHQUFBLEVBQUEsVUFBQSxFQUFBLENBQUEsRUFBQTtBQUNBLGVBQUEsT0FBQSxDQUFBLENBQUEsSUFBQSxVQUFBOztBQUVBLFlBQUEsU0FBQSxFQUFBLFFBQUEsT0FBQSxlQUFBLENBQUEsQ0FBQSxDQUFBLEVBQUEsUUFBQSxVQUFBLEVBQUE7OztBQUdBLFlBQUEsT0FBQSxlQUFBLENBQUEsTUFBQSxLQUFBLENBQUEsRUFBQTtBQUFBLG1CQUFBLGVBQUEsQ0FBQSxJQUFBLENBQUEsTUFBQTtBQUFBLFNBQUEsTUFBQTtBQUNBLGlCQUFBLElBQUEsSUFBQSxDQUFBLEVBQUEsSUFBQSxPQUFBLGVBQUEsQ0FBQSxNQUFBLEVBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsT0FBQSxlQUFBLENBQUEsQ0FBQSxFQUFBLE1BQUEsS0FBQSxPQUFBLE1BQUEsRUFBQTtBQUNBLDJCQUFBLGVBQUEsQ0FBQSxDQUFBLElBQUEsTUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLG1CQUFBLGVBQUEsQ0FBQSxJQUFBLENBQUEsTUFBQTtBQUNBOztBQUVBLEtBaEJBOzs7O0FBb0JBLFdBQUEsZUFBQSxHQUFBLEVBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsVUFBQSxHQUFBLEVBQUEsT0FBQSxFQUFBLEdBQUEsRUFBQSxDQUFBLEVBQUEsQ0FBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLE9BQUEsZUFBQTtBQUNBLFlBQUEsUUFBQSxLQUFBO0FBQ0EsWUFBQSxVQUFBLEtBQUEsQ0FBQSxDQUFBO0FBQ0EsYUFBQSxJQUFBLElBQUEsQ0FBQSxFQUFBLElBQUEsT0FBQSxlQUFBLENBQUEsTUFBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLE1BQUEsT0FBQSxlQUFBLENBQUEsQ0FBQSxDQUFBO0FBQ0Esb0JBQUEsR0FBQSxDQUFBLEdBQUE7QUFDQSxnQkFBQSxJQUFBLElBQUEsTUFBQSxDQUFBLEVBQUE7QUFDQSx3QkFBQSxJQUFBO0FBQ0Esb0JBQUEsSUFBQSxPQUFBLENBQUEsRUFBQSxJQUFBLE9BQUEsSUFBQSxPQUFBO0FBQ0Esb0JBQUEsT0FBQSxJQUFBLE9BQUE7QUFDQTtBQUNBO0FBQ0EsWUFBQSxDQUFBLEtBQUEsRUFBQTtBQUNBLGdCQUFBLFNBQUEsRUFBQTtBQUNBLG1CQUFBLElBQUEsSUFBQSxDQUFBO0FBQ0EsbUJBQUEsT0FBQSxJQUFBLE9BQUE7QUFDQSxtQkFBQSxlQUFBLENBQUEsSUFBQSxDQUFBLE1BQUE7QUFDQTtBQUNBLEtBbkJBOztBQXFCQSxXQUFBLGFBQUEsR0FBQSxZQUFBO0FBQ0EsWUFBQSxPQUFBLEVBQUEsTUFBQSxPQUFBLGVBQUEsRUFBQSxTQUFBLE9BQUEsZUFBQSxFQUFBO0FBQ0EscUJBQUEsYUFBQSxDQUFBLE9BQUEsU0FBQSxFQUFBLE9BQUEsWUFBQSxFQUFBLElBQUE7QUFDQSxLQUhBOztBQU1BLFdBQUEsV0FBQSxHQUFBLFlBQUE7QUFDQSxxQkFBQSxXQUFBLENBQUEsT0FBQSxZQUFBLEVBQ0EsSUFEQSxDQUNBLFlBQUE7QUFDQSxtQkFBQSxFQUFBLENBQUEsT0FBQSxFQUFBLEVBQUEsUUFBQSxPQUFBLFNBQUEsRUFBQSxFQUFBLEVBQUEsUUFBQSxJQUFBLEVBQUE7QUFDQSxTQUhBO0FBSUEsS0FMQTs7OztBQVNBLFdBQUEsd0JBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsYUFBQSxHQUFBLEVBQUE7O0FBRUEsaUJBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxJQUFBLE1BQUEsS0FBQSxPQUFBLFlBQUEsSUFBQSxPQUFBLHdCQUFBLENBQUEsT0FBQSxDQUFBLElBQUEsTUFBQSxLQUFBLENBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsd0JBQUEsQ0FBQSxJQUFBLENBQUEsSUFBQSxNQUFBO0FBQ0EsU0FGQSxNQUVBLElBQUEsSUFBQSxNQUFBLEtBQUEsT0FBQSxZQUFBLElBQUEsT0FBQSx3QkFBQSxDQUFBLE9BQUEsQ0FBQSxJQUFBLE1BQUEsS0FBQSxDQUFBLENBQUEsRUFBQTtBQUNBLG1CQUFBLHdCQUFBLENBQUEsSUFBQSxDQUFBLElBQUEsTUFBQTtBQUNBO0FBQ0EsS0FOQTs7QUFRQSxXQUFBLGFBQUEsR0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxhQUFBLENBQUEsT0FBQSxDQUFBLE9BQUEsd0JBQUEsQ0FBQSxHQUFBLENBQUEsTUFBQSxDQUFBLENBQUEsRUFBQTtBQUNBLG1CQUFBLGFBQUEsQ0FBQSxJQUFBLENBQUEsT0FBQSx3QkFBQSxDQUFBLEdBQUEsQ0FBQTtBQUNBLFNBRkEsTUFFQTtBQUNBLGdCQUFBLElBQUEsT0FBQSxhQUFBLENBQUEsT0FBQSxDQUFBLE9BQUEsd0JBQUEsQ0FBQSxHQUFBLENBQUEsQ0FBQTtBQUNBLG1CQUFBLGFBQUEsQ0FBQSxNQUFBLENBQUEsQ0FBQSxFQUFBLENBQUE7QUFDQTtBQUNBLEtBUEE7O0FBU0EsV0FBQSxlQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLGtCQUFBLEdBQUEsWUFBQTtBQUNBLFlBQUEscUJBQUEsRUFBQTtBQUNBLGVBQUEsYUFBQSxDQUFBLE9BQUEsQ0FBQSxVQUFBLFNBQUEsRUFBQTtBQUNBLG1CQUFBLG1CQUFBLElBQUEsQ0FBQSxhQUFBLGtCQUFBLENBQUEsT0FBQSxTQUFBLEVBQUEsU0FBQSxDQUFBLENBQUE7QUFDQSxTQUZBO0FBR0EsZ0JBQUEsR0FBQSxDQUFBLGtCQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsT0FBQSxFQUFBO0FBQ0Esb0JBQUEsT0FBQSxDQUFBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsdUJBQUEsZUFBQSxDQUFBLElBQUEsQ0FBQSxNQUFBO0FBQ0EsdUJBQUEsVUFBQTtBQUNBLGFBSEE7QUFJQSxTQU5BO0FBUUEsS0FiQTs7QUFlQSxRQUFBLGtCQUFBLEVBQUE7QUFDQSxRQUFBLFVBQUE7O0FBRUEsV0FBQSxrQkFBQSxHQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxDQUFBLGVBQUEsRUFBQSxrQkFBQSxFQUFBOztBQUVBLFlBQUEsYUFBQSxPQUFBLGVBQUEsQ0FBQSxDQUFBLEVBQUEsU0FBQSxFQUFBLElBQUEsQ0FBQSxDQUFBO0FBQ0EsWUFBQSxZQUFBLElBQUEsU0FBQTtBQUNBLHFCQUFBLFNBQUE7O0FBRUEsWUFBQSxDQUFBLGdCQUFBLFNBQUEsQ0FBQSxFQUFBLGdCQUFBLFNBQUEsSUFBQSxFQUFBO0FBQ0EsWUFBQSxnQkFBQSxTQUFBLEVBQUEsT0FBQSxDQUFBLFVBQUEsTUFBQSxDQUFBLENBQUEsRUFBQTtBQUNBLDRCQUFBLFNBQUEsRUFBQSxNQUFBLENBQUEsZ0JBQUEsU0FBQSxFQUFBLE9BQUEsQ0FBQSxVQUFBLENBQUEsRUFBQSxDQUFBO0FBQ0EsU0FGQSxNQUVBO0FBQ0EsNEJBQUEsU0FBQSxFQUFBLElBQUEsQ0FBQSxVQUFBO0FBQ0E7QUFDQSxlQUFBLGVBQUEsR0FBQSxlQUFBO0FBQ0EsS0FkQTs7O0FBa0JBLFdBQUEsYUFBQSxHQUFBLEVBQUE7O0FBRUEsV0FBQSxXQUFBOztBQUVBLFdBQUEsR0FBQSxHQUFBLEVBQUE7Ozs7QUFLQSxXQUFBLE9BQUEsR0FBQSxZQUFBOztBQUVBLFlBQUEsa0JBQUEsT0FBQSxPQUFBLENBQUEsR0FBQSxDQUFBLFVBQUEsT0FBQSxFQUFBO0FBQ0EsbUJBQUEsT0FBQSxZQUFBLEdBQUEsR0FBQSxHQUFBLE9BQUE7QUFDQSxTQUZBLENBQUE7QUFHQSxhQUFBLElBQUEsSUFBQSxJQUFBLE9BQUEsZUFBQSxFQUFBO0FBQ0EsbUJBQUEsZUFBQSxDQUFBLElBQUEsRUFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQ0FBQSxJQUFBLENBQUEsT0FBQSxHQUFBLEdBQUEsR0FBQTtBQUNBLGFBRkE7QUFHQTtBQUNBLHFCQUFBLE9BQUEsQ0FBQSxPQUFBLFNBQUEsRUFBQSxPQUFBLFlBQUEsRUFBQSxPQUFBLGFBQUEsRUFBQSxPQUFBLGVBQUEsRUFBQSxPQUFBLFlBQUEsRUFBQSxlQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsV0FBQSxFQUFBO0FBQ0EsbUJBQUEsV0FBQSxHQUFBLFdBQUE7QUFDQSxTQUhBLEVBSUEsSUFKQSxDQUlBLFlBQUE7QUFDQSxtQkFBQSxFQUFBLENBQUEsb0JBQUE7QUFDQSxTQU5BO0FBT0EsS0FqQkE7QUFtQkEsQ0F0WUE7O0FDQUEsSUFBQSxVQUFBLENBQUEsV0FBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxNQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQSxTQUFBLEVBQUEsV0FBQSxFQUFBLFlBQUEsRUFBQSxVQUFBLEVBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsU0FBQTs7QUFFQSxXQUFBLFdBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsTUFBQSxHQUFBLGFBQUEsTUFBQTs7QUFFQSxXQUFBLFlBQUEsR0FBQSxZQUFBOztBQUVBLFdBQUEsVUFBQSxHQUFBLFVBQUE7O0FBRUEsV0FBQSxnQkFBQSxHQUFBLGFBQUEsTUFBQSxHQUFBLFFBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsT0FBQSxTQUFBLENBQUEsSUFBQSxDQUFBLE1BQUE7O0FBRUEsV0FBQSxHQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsV0FBQSxDQUFBLElBQUEsQ0FBQSxHQUFBO0FBQ0EsS0FGQTs7QUFJQSxXQUFBLE1BQUEsR0FBQSxNQUFBLEM7O0FBRUEsV0FBQSxnQkFBQSxHQUFBLENBQUEsUUFBQSxFQUFBLFNBQUEsQ0FBQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxhQUFBLE1BQUE7O0FBRUEsV0FBQSxnQkFBQSxHQUFBLFVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTtBQUNBLHFCQUFBLGdCQUFBLENBQUEsV0FBQSxFQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxPQUFBLEVBQUEsRUFBQSxRQUFBLE9BQUEsTUFBQSxFQUFBLEVBQUEsRUFBQSxRQUFBLElBQUEsRUFBQTtBQUNBLFNBSEE7QUFJQSxLQUxBOztBQU9BLFdBQUEsWUFBQSxHQUFBLFVBQUEsU0FBQSxFQUFBO0FBQ0EsWUFBQSxjQUFBLGVBQUEsSUFBQSxjQUFBLG1CQUFBLEVBQUEsT0FBQSxJQUFBO0FBQ0EsS0FGQTs7QUFJQSxXQUFBLFdBQUEsR0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLHFCQUFBLFdBQUEsQ0FBQSxLQUFBLEVBQ0EsSUFEQSxDQUNBLFlBQUE7QUFDQSxtQkFBQSxFQUFBLENBQUEsT0FBQSxFQUFBLEVBQUEsUUFBQSxPQUFBLE1BQUEsRUFBQTtBQUNBLFNBSEE7QUFJQSxLQUxBOztBQU9BLFdBQUEsY0FBQSxHQUFBLFlBQUE7QUFDQSxlQUFBLFVBQUEsQ0FBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxJQUFBLFVBQUEsS0FBQSxPQUFBLEtBQUEsQ0FBQSxNQUFBLElBQUEsSUFBQSxXQUFBLEtBQUEsT0FBQSxLQUFBLENBQUEsTUFBQSxFQUFBLE9BQUEsSUFBQSxHQUFBLElBQUEsU0FBQTtBQUNBLFNBRkE7QUFHQSxLQUpBOztBQU1BLFdBQUEsYUFBQSxHQUFBLEVBQUE7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQTJCQSxXQUFBLFdBQUEsR0FBQSxhQUFBLFdBQUE7QUFFQSxDQS9FQTs7QUNBQSxJQUFBLE9BQUEsQ0FBQSxjQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUEsWUFBQSxFQUFBOztBQUVBLFFBQUEsZUFBQSxFQUFBOztBQUVBLGFBQUEsU0FBQSxDQUFBLEdBQUEsRUFBQTtBQUNBLGVBQUEsSUFBQSxJQUFBO0FBQ0E7O0FBRUEsaUJBQUEsWUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQkFBQSxNQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsY0FBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsU0FBQSxHQUFBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQkFBQSxNQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsTUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxJQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxHQUFBLFNBQUEsRUFBQSxJQUFBLENBQUE7QUFDQSxLQUZBOztBQUlBLGlCQUFBLGFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsSUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxrQkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsRUFBQSxJQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsTUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxDQUFBLHlCQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxFQUFBLEVBQUEsV0FBQSxTQUFBLEVBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxTQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLEtBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEdBQUEsR0FBQSxHQUFBLEtBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxZQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLFVBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEdBQUEsVUFBQSxHQUFBLFVBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxTQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxJQUFBLENBQUEsNEJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsQ0FBQTtBQUNBLEtBRkE7QUFHQSxpQkFBQSxXQUFBLEdBQUEsVUFBQSxLQUFBLEVBQUE7QUFDQSxjQUFBLE1BQUEsR0FBQSxhQUFBLE1BQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxDQUFBLGVBQUEsRUFBQSxLQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSkE7O0FBTUEsaUJBQUEsV0FBQSxHQUFBLFVBQUEsWUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLE1BQUEsQ0FBQSxtQkFBQSxhQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsYUFBQSxTQUFBLENBQUE7QUFDQSxLQUZBOztBQUlBLGlCQUFBLGdCQUFBLEdBQUEsVUFBQSxXQUFBLEVBQUEsTUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLElBQUEsQ0FBQSxtQkFBQSxNQUFBLEdBQUEsY0FBQSxFQUFBLFdBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxRQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsTUFBQSxDQUFBLG1CQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxlQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdB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QUFNQSxnQkFBQSxhQUFBLFNBQUEsVUFBQSxHQUFBO0FBQ0Esc0JBQUEsSUFBQSxHQUFBLElBQUE7QUFDQSxhQUZBOztBQUlBOztBQUVBLHVCQUFBLEdBQUEsQ0FBQSxZQUFBLFlBQUEsRUFBQSxPQUFBO0FBQ0EsdUJBQUEsR0FBQSxDQUFBLFlBQUEsYUFBQSxFQUFBLFVBQUE7QUFDQSx1QkFBQSxHQUFBLENBQUEsWUFBQSxjQUFBLEVBQUEsVUFBQTtBQUVBOztBQXpDQSxLQUFBO0FBNkNBLENBL0NBOztBQ0FBLElBQUEsU0FBQSxDQUFBLGVBQUEsRUFBQSxVQUFBLGVBQUEsRUFBQTs7QUFFQSxXQUFBO0FBQ0Esa0JBQUEsR0FEQTtBQUVBLHFCQUFBLHlEQUZBO0FBR0EsY0FBQSxjQUFBLEtBQUEsRUFBQTtBQUNBLGtCQUFBLFFBQUEsR0FBQSxnQkFBQSxpQkFBQSxFQUFBO0FBQ0E7QUFMQSxLQUFBO0FBUUEsQ0FWQSIsImZpbGUiOiJtYWluLmpzIiwic291cmNlc0NvbnRlbnQiOlsiJ3VzZSBzdHJpY3QnO1xud2luZG93LmFwcCA9IGFuZ3VsYXIubW9kdWxlKCdGdWxsc3RhY2tHZW5lcmF0ZWRBcHAnLCBbJ2ZzYVByZUJ1aWx0JywgJ3VpLnJvdXRlcicsICd1aS5ib290c3RyYXAnLCAnbmdBbmltYXRlJ10pO1xuXG5hcHAuY29uZmlnKGZ1bmN0aW9uICgkdXJsUm91dGVyUHJvdmlkZXIsICRsb2NhdGlvblByb3ZpZGVyKSB7XG4gICAgLy8gVGhpcyB0dXJucyBvZmYgaGFzaGJhbmcgdXJscyAoLyNhYm91dCkgYW5kIGNoYW5nZXMgaXQgdG8gc29tZXRoaW5nIG5vcm1hbCAoL2Fib3V0KVxuICAgICRsb2NhdGlvblByb3ZpZGVyLmh0bWw1TW9kZSh0cnVlKTtcbiAgICAvLyBJZiB3ZSBnbyB0byBhIFVSTCB0aGF0IHVpLXJvdXRlciBkb2Vzbid0IGhhdmUgcmVnaXN0ZXJlZCwgZ28gdG8gdGhlIFwiL1wiIHVybC5cbiAgICAkdXJsUm91dGVyUHJvdmlkZXIub3RoZXJ3aXNlKCcvJyk7XG4gICAgLy8gVHJpZ2dlciBwYWdlIHJlZnJlc2ggd2hlbiBhY2Nlc3NpbmcgYW4gT0F1dGggcm91dGVcbiAgICAkdXJsUm91dGVyUHJvdmlkZXIud2hlbignL2F1dGgvOnByb3ZpZGVyJywgZnVuY3Rpb24gKCkge1xuICAgICAgICB3aW5kb3cubG9jYXRpb24ucmVsb2FkKCk7XG4gICAgfSk7XG59KTtcblxuLy8gVGhpcyBhcHAucnVuIGlzIGZvciBjb250cm9sbGluZyBhY2Nlc3MgdG8gc3BlY2lmaWMgc3RhdGVzLlxuYXBwLnJ1bihmdW5jdGlvbiAoJHJvb3RTY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICAgLy8gVGhlIGdpdmVuIHN0YXRlIHJlcXVpcmVzIGFuIGF1dGhlbnRpY2F0ZWQgdXNlci5cbiAgICB2YXIgZGVzdGluYXRpb25TdGF0ZVJlcXVpcmVzQXV0aCA9IGZ1bmN0aW9uIChzdGF0ZSkge1xuICAgICAgICByZXR1cm4gc3RhdGUuZGF0YSAmJiBzdGF0ZS5kYXRhLmF1dGhlbnRpY2F0ZTtcbiAgICB9O1xuXG4gICAgLy8gJHN0YXRlQ2hhbmdlU3RhcnQgaXMgYW4gZXZlbnQgZmlyZWRcbiAgICAvLyB3aGVuZXZlciB0aGUgcHJvY2VzcyBvZiBjaGFuZ2luZyBhIHN0YXRlIGJlZ2lucy5cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbiAoZXZlbnQsIHRvU3RhdGUsIHRvUGFyYW1zKSB7XG5cbiAgICAgICAgaWYgKCFkZXN0aW5hdGlvblN0YXRlUmVxdWlyZXNBdXRoKHRvU3RhdGUpKSB7XG4gICAgICAgICAgICAvLyBUaGUgZGVzdGluYXRpb24gc3RhdGUgZG9lcyBub3QgcmVxdWlyZSBhdXRoZW50aWNhdGlvblxuICAgICAgICAgICAgLy8gU2hvcnQgY2lyY3VpdCB3aXRoIHJldHVybi5cbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChBdXRoU2VydmljZS5pc0F1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAgICAgLy8gVGhlIHVzZXIgaXMgYXV0aGVudGljYXRlZC5cbiAgICAgICAgICAgIC8vIFNob3J0IGNpcmN1aXQgd2l0aCByZXR1cm4uXG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDYW5jZWwgbmF2aWdhdGluZyB0byBuZXcgc3RhdGUuXG4gICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG5cbiAgICAgICAgQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCkudGhlbihmdW5jdGlvbiAodXNlcikge1xuICAgICAgICAgICAgLy8gSWYgYSB1c2VyIGlzIHJldHJpZXZlZCwgdGhlbiByZW5hdmlnYXRlIHRvIHRoZSBkZXN0aW5hdGlvblxuICAgICAgICAgICAgLy8gKHRoZSBzZWNvbmQgdGltZSwgQXV0aFNlcnZpY2UuaXNBdXRoZW50aWNhdGVkKCkgd2lsbCB3b3JrKVxuICAgICAgICAgICAgLy8gb3RoZXJ3aXNlLCBpZiBubyB1c2VyIGlzIGxvZ2dlZCBpbiwgZ28gdG8gXCJsb2dpblwiIHN0YXRlLlxuICAgICAgICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgICAgICAgICAkc3RhdGUuZ28odG9TdGF0ZS5uYW1lLCB0b1BhcmFtcyk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnbG9naW4nKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG5cbiAgICB9KTtcblxufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuXG4gICAgLy8gUmVnaXN0ZXIgb3VyICphYm91dCogc3RhdGUuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2Fib3V0Jywge1xuICAgICAgICB1cmw6ICcvYWJvdXQnLFxuICAgICAgICBjb250cm9sbGVyOiAnQWJvdXRDb250cm9sbGVyJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9hYm91dC9hYm91dC5odG1sJ1xuICAgIH0pO1xuXG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ0Fib3V0Q29udHJvbGxlcicsIGZ1bmN0aW9uICgkc2NvcGUsIEZ1bGxzdGFja1BpY3MpIHtcblxuICAgIC8vIEltYWdlcyBvZiBiZWF1dGlmdWwgRnVsbHN0YWNrIHBlb3BsZS5cbiAgICAkc2NvcGUuaW1hZ2VzID0gXy5zaHVmZmxlKEZ1bGxzdGFja1BpY3MpO1xuXG59KTsiLCJhcHAuY29udHJvbGxlcignQ3JlYXRlZGJDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHN0YXRlLCBDcmVhdGVkYkZhY3RvcnkpIHtcblxuXHQkc2NvcGUuY3JlYXRlZERCID0gZmFsc2U7XG4gICAgICAgICRzY29wZS5jb2x1bW5BcnJheSA9IFtdO1xuXG5cdCRzY29wZS5hZGQgPSBmdW5jdGlvbigpIHtcblx0XHQkc2NvcGUuY29sdW1uQXJyYXkucHVzaCgnMScpO1xuXHR9XG5cblx0JHNjb3BlLmNyZWF0ZURCID0gZnVuY3Rpb24obmFtZSkge1xuXHRcdENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVEQihuYW1lKVxuXHRcdC50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcblx0XHRcdCRzY29wZS5jcmVhdGVkREIgPSBkYXRhO1xuXHRcdH0pXG5cdH1cblxuXHQkc2NvcGUuY3JlYXRlVGFibGUgPSBmdW5jdGlvbih0YWJsZSwgREIpe1xuXHRcdENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVUYWJsZSh0YWJsZSwgREIpXG5cdFx0XHQkc3RhdGUuZ28oJ1RhYmxlJywge2RiTmFtZTogJHNjb3BlLmNyZWF0ZWREQi5kYk5hbWV9LCB7cmVsb2FkOnRydWV9KVxuXHR9XG59KTtcbiIsImFwcC5mYWN0b3J5KCdDcmVhdGVkYkZhY3RvcnknLCBmdW5jdGlvbiAoJGh0dHApIHtcblxuXHR2YXIgQ3JlYXRlZGJGYWN0b3J5ID0ge307XG5cblx0ZnVuY3Rpb24gcmVzVG9EYXRhKHJlcykge1xuICAgICAgICByZXR1cm4gcmVzLmRhdGE7XG4gICAgfVxuXG4gICAgQ3JlYXRlZGJGYWN0b3J5LmNyZWF0ZURCID0gZnVuY3Rpb24oZGJOYW1lKSB7XG4gICAgXHRyZXR1cm4gJGh0dHAucG9zdCgnL2FwaS9tYXN0ZXJkYicsIGRiTmFtZSlcbiAgICBcdC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgIENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVUYWJsZSA9IGZ1bmN0aW9uKHRhYmxlLCBjcmVhdGVkREIpIHtcbiAgICB0YWJsZS5kYk5hbWUgPSBjcmVhdGVkREIuZGJOYW1lO1xuICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL2NsaWVudGRiJywgdGFibGUpXG4gICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgIH1cblxuXHRyZXR1cm4gQ3JlYXRlZGJGYWN0b3J5OyBcbn0pXG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdjcmVhdGVkYicsIHtcbiAgICAgICAgdXJsOiAnL2NyZWF0ZWRiJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jcmVhdGVkYi9jcmVhdGVkYi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0NyZWF0ZWRiQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgXHRsb2dnZWRJblVzZXI6IGZ1bmN0aW9uKEF1dGhTZXJ2aWNlKSB7XG4gICAgICAgIFx0XHRyZXR1cm4gQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCk7XG4gICAgICAgIFx0fVxuICAgICAgICB9XG4gICAgfSk7XG5cbn0pOyIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2RvY3MnLCB7XG4gICAgICAgIHVybDogJy9kb2NzJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9kb2NzL2RvY3MuaHRtbCdcbiAgICB9KTtcbn0pO1xuIiwiKGZ1bmN0aW9uICgpIHtcblxuICAgICd1c2Ugc3RyaWN0JztcblxuICAgIC8vIEhvcGUgeW91IGRpZG4ndCBmb3JnZXQgQW5ndWxhciEgRHVoLWRveS5cbiAgICBpZiAoIXdpbmRvdy5hbmd1bGFyKSB0aHJvdyBuZXcgRXJyb3IoJ0kgY2FuXFwndCBmaW5kIEFuZ3VsYXIhJyk7XG5cbiAgICB2YXIgYXBwID0gYW5ndWxhci5tb2R1bGUoJ2ZzYVByZUJ1aWx0JywgW10pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ1NvY2tldCcsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKCF3aW5kb3cuaW8pIHRocm93IG5ldyBFcnJvcignc29ja2V0LmlvIG5vdCBmb3VuZCEnKTtcbiAgICAgICAgcmV0dXJuIHdpbmRvdy5pbyh3aW5kb3cubG9jYXRpb24ub3JpZ2luKTtcbiAgICB9KTtcblxuICAgIC8vIEFVVEhfRVZFTlRTIGlzIHVzZWQgdGhyb3VnaG91dCBvdXIgYXBwIHRvXG4gICAgLy8gYnJvYWRjYXN0IGFuZCBsaXN0ZW4gZnJvbSBhbmQgdG8gdGhlICRyb290U2NvcGVcbiAgICAvLyBmb3IgaW1wb3J0YW50IGV2ZW50cyBhYm91dCBhdXRoZW50aWNhdGlvbiBmbG93LlxuICAgIGFwcC5jb25zdGFudCgnQVVUSF9FVkVOVFMnLCB7XG4gICAgICAgIGxvZ2luU3VjY2VzczogJ2F1dGgtbG9naW4tc3VjY2VzcycsXG4gICAgICAgIGxvZ2luRmFpbGVkOiAnYXV0aC1sb2dpbi1mYWlsZWQnLFxuICAgICAgICBsb2dvdXRTdWNjZXNzOiAnYXV0aC1sb2dvdXQtc3VjY2VzcycsXG4gICAgICAgIHNlc3Npb25UaW1lb3V0OiAnYXV0aC1zZXNzaW9uLXRpbWVvdXQnLFxuICAgICAgICBub3RBdXRoZW50aWNhdGVkOiAnYXV0aC1ub3QtYXV0aGVudGljYXRlZCcsXG4gICAgICAgIG5vdEF1dGhvcml6ZWQ6ICdhdXRoLW5vdC1hdXRob3JpemVkJ1xuICAgIH0pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ0F1dGhJbnRlcmNlcHRvcicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCAkcSwgQVVUSF9FVkVOVFMpIHtcbiAgICAgICAgdmFyIHN0YXR1c0RpY3QgPSB7XG4gICAgICAgICAgICA0MDE6IEFVVEhfRVZFTlRTLm5vdEF1dGhlbnRpY2F0ZWQsXG4gICAgICAgICAgICA0MDM6IEFVVEhfRVZFTlRTLm5vdEF1dGhvcml6ZWQsXG4gICAgICAgICAgICA0MTk6IEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LFxuICAgICAgICAgICAgNDQwOiBBVVRIX0VWRU5UUy5zZXNzaW9uVGltZW91dFxuICAgICAgICB9O1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KHN0YXR1c0RpY3RbcmVzcG9uc2Uuc3RhdHVzXSwgcmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVzcG9uc2UpXG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgfSk7XG5cbiAgICBhcHAuY29uZmlnKGZ1bmN0aW9uICgkaHR0cFByb3ZpZGVyKSB7XG4gICAgICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goW1xuICAgICAgICAgICAgJyRpbmplY3RvcicsXG4gICAgICAgICAgICBmdW5jdGlvbiAoJGluamVjdG9yKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRpbmplY3Rvci5nZXQoJ0F1dGhJbnRlcmNlcHRvcicpO1xuICAgICAgICAgICAgfVxuICAgICAgICBdKTtcbiAgICB9KTtcblxuICAgIGFwcC5zZXJ2aWNlKCdBdXRoU2VydmljZScsIGZ1bmN0aW9uICgkaHR0cCwgU2Vzc2lvbiwgJHJvb3RTY29wZSwgQVVUSF9FVkVOVFMsICRxKSB7XG5cbiAgICAgICAgZnVuY3Rpb24gb25TdWNjZXNzZnVsTG9naW4ocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHZhciBkYXRhID0gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgICAgIFNlc3Npb24uY3JlYXRlKGRhdGEuaWQsIGRhdGEudXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3QoQVVUSF9FVkVOVFMubG9naW5TdWNjZXNzKTtcbiAgICAgICAgICAgIHJldHVybiBkYXRhLnVzZXI7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBVc2VzIHRoZSBzZXNzaW9uIGZhY3RvcnkgdG8gc2VlIGlmIGFuXG4gICAgICAgIC8vIGF1dGhlbnRpY2F0ZWQgdXNlciBpcyBjdXJyZW50bHkgcmVnaXN0ZXJlZC5cbiAgICAgICAgdGhpcy5pc0F1dGhlbnRpY2F0ZWQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gISFTZXNzaW9uLnVzZXI7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5nZXRMb2dnZWRJblVzZXIgPSBmdW5jdGlvbiAoZnJvbVNlcnZlcikge1xuXG4gICAgICAgICAgICAvLyBJZiBhbiBhdXRoZW50aWNhdGVkIHNlc3Npb24gZXhpc3RzLCB3ZVxuICAgICAgICAgICAgLy8gcmV0dXJuIHRoZSB1c2VyIGF0dGFjaGVkIHRvIHRoYXQgc2Vzc2lvblxuICAgICAgICAgICAgLy8gd2l0aCBhIHByb21pc2UuIFRoaXMgZW5zdXJlcyB0aGF0IHdlIGNhblxuICAgICAgICAgICAgLy8gYWx3YXlzIGludGVyZmFjZSB3aXRoIHRoaXMgbWV0aG9kIGFzeW5jaHJvbm91c2x5LlxuXG4gICAgICAgICAgICAvLyBPcHRpb25hbGx5LCBpZiB0cnVlIGlzIGdpdmVuIGFzIHRoZSBmcm9tU2VydmVyIHBhcmFtZXRlcixcbiAgICAgICAgICAgIC8vIHRoZW4gdGhpcyBjYWNoZWQgdmFsdWUgd2lsbCBub3QgYmUgdXNlZC5cblxuICAgICAgICAgICAgaWYgKHRoaXMuaXNBdXRoZW50aWNhdGVkKCkgJiYgZnJvbVNlcnZlciAhPT0gdHJ1ZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS53aGVuKFNlc3Npb24udXNlcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIE1ha2UgcmVxdWVzdCBHRVQgL3Nlc3Npb24uXG4gICAgICAgICAgICAvLyBJZiBpdCByZXR1cm5zIGEgdXNlciwgY2FsbCBvblN1Y2Nlc3NmdWxMb2dpbiB3aXRoIHRoZSByZXNwb25zZS5cbiAgICAgICAgICAgIC8vIElmIGl0IHJldHVybnMgYSA0MDEgcmVzcG9uc2UsIHdlIGNhdGNoIGl0IGFuZCBpbnN0ZWFkIHJlc29sdmUgdG8gbnVsbC5cbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9zZXNzaW9uJykudGhlbihvblN1Y2Nlc3NmdWxMb2dpbikuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLnNpZ251cCA9IGZ1bmN0aW9uKGNyZWRlbnRpYWxzKXtcbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvc2lnbnVwJywgY3JlZGVudGlhbHMpXG4gICAgICAgICAgICAudGhlbihvblN1Y2Nlc3NmdWxMb2dpbilcbiAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdCh7IG1lc3NhZ2U6ICdJbnZhbGlkIHNpZ251cCBjcmVkZW50aWFscy4nIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5sb2dpbiA9IGZ1bmN0aW9uIChjcmVkZW50aWFscykge1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9sb2dpbicsIGNyZWRlbnRpYWxzKVxuICAgICAgICAgICAgICAgIC50aGVuKG9uU3VjY2Vzc2Z1bExvZ2luKVxuICAgICAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QoeyBtZXNzYWdlOiAnSW52YWxpZCBsb2dpbiBjcmVkZW50aWFscy4nIH0pO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2xvZ291dCcpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIFNlc3Npb24uZGVzdHJveSgpO1xuICAgICAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChBVVRIX0VWRU5UUy5sb2dvdXRTdWNjZXNzKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuXG4gICAgfSk7XG5cbiAgICBhcHAuc2VydmljZSgnU2Vzc2lvbicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBVVRIX0VWRU5UUykge1xuXG4gICAgICAgIHZhciBzZWxmID0gdGhpcztcblxuICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5ub3RBdXRoZW50aWNhdGVkLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBzZWxmLmRlc3Ryb3koKTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHNlbGYuZGVzdHJveSgpO1xuICAgICAgICB9KTtcblxuICAgICAgICB0aGlzLmlkID0gbnVsbDtcbiAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcblxuICAgICAgICB0aGlzLmNyZWF0ZSA9IGZ1bmN0aW9uIChzZXNzaW9uSWQsIHVzZXIpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBzZXNzaW9uSWQ7XG4gICAgICAgICAgICB0aGlzLnVzZXIgPSB1c2VyO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMuZGVzdHJveSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBudWxsO1xuICAgICAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcbiAgICAgICAgfTtcblxuICAgIH0pO1xuXG59KSgpO1xuIiwiYXBwLmNvbnRyb2xsZXIoJ0hvbWVDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgYWxsRGJzLCAkc3RhdGUpIHtcblxuXHQkc2NvcGUuYWxsRGJzID0gYWxsRGJzO1xufSk7XG4iLCJhcHAuZmFjdG9yeSgnSG9tZUZhY3RvcnknLCBmdW5jdGlvbiAoJGh0dHApIHtcblxuXHR2YXIgSG9tZUZhY3RvcnkgPSB7fTtcblxuXHRmdW5jdGlvbiByZXNUb0RhdGEocmVzKSB7XG4gICAgICAgIHJldHVybiByZXMuZGF0YTtcbiAgICB9XG5cbiAgICBIb21lRmFjdG9yeS5nZXRBbGxEYnMgPSBmdW5jdGlvbigpe1xuICAgIFx0cmV0dXJuICRodHRwLmdldCgnL2FwaS9tYXN0ZXJkYicpXG4gICAgXHQudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgSG9tZUZhY3RvcnkuZGVsZXRlREIgPSBmdW5jdGlvbihuYW1lKXtcbiAgICBcdHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvbWFzdGVyZGIvJyArIG5hbWUpXG4gICAgXHQudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG5cdHJldHVybiBIb21lRmFjdG9yeTsgXG59KSIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ0hvbWUnLCB7XG4gICAgICAgIHVybDogJy9ob21lJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9Ib21lL0hvbWUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdIb21lQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgXHRhbGxEYnM6IGZ1bmN0aW9uKEhvbWVGYWN0b3J5KXtcbiAgICAgICAgXHRcdHJldHVybiBIb21lRmFjdG9yeS5nZXRBbGxEYnMoKTtcbiAgICAgICAgXHR9LFxuICAgICAgICAgICAgbG9nZ2VkSW5Vc2VyOiBmdW5jdGlvbiAoQXV0aFNlcnZpY2UpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KTtcbn0pOyIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2xhbmRpbmdQYWdlJywge1xuICAgICAgICB1cmw6ICcvJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9sYW5kaW5nUGFnZS9sYW5kaW5nUGFnZS5odG1sJ1xuICAgICAgICB9XG4gICAgKTtcblxufSk7IiwiYXBwLmNvbmZpZyhmdW5jdGlvbigkc3RhdGVQcm92aWRlcikge1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2xvZ2luJywge1xuICAgICAgICB1cmw6ICcvbG9naW4nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2xvZ2luL2xvZ2luLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnTG9naW5DdHJsJ1xuICAgIH0pO1xuXG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ0xvZ2luQ3RybCcsIGZ1bmN0aW9uKCRzY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICAgJHNjb3BlLmxvZ2luID0ge307XG4gICAgJHNjb3BlLmVycm9yID0gbnVsbDtcblxuICAgICRzY29wZS5zZW5kTG9naW4gPSBmdW5jdGlvbihsb2dpbkluZm8pIHtcblxuICAgICAgICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICAgICAgIEF1dGhTZXJ2aWNlLmxvZ2luKGxvZ2luSW5mbykudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbygnSG9tZScpO1xuICAgICAgICB9KS5jYXRjaChmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICRzY29wZS5lcnJvciA9ICdJbnZhbGlkIGxvZ2luIGNyZWRlbnRpYWxzLic7XG4gICAgICAgIH0pO1xuXG4gICAgfTtcblxufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ21lbWJlcnNPbmx5Jywge1xuICAgICAgICB1cmw6ICcvbWVtYmVycy1hcmVhJyxcbiAgICAgICAgdGVtcGxhdGU6ICc8aW1nIG5nLXJlcGVhdD1cIml0ZW0gaW4gc3Rhc2hcIiB3aWR0aD1cIjMwMFwiIG5nLXNyYz1cInt7IGl0ZW0gfX1cIiAvPicsXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uICgkc2NvcGUsIFNlY3JldFN0YXNoKSB7XG4gICAgICAgICAgICBTZWNyZXRTdGFzaC5nZXRTdGFzaCgpLnRoZW4oZnVuY3Rpb24gKHN0YXNoKSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnN0YXNoID0gc3Rhc2g7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSxcbiAgICAgICAgLy8gVGhlIGZvbGxvd2luZyBkYXRhLmF1dGhlbnRpY2F0ZSBpcyByZWFkIGJ5IGFuIGV2ZW50IGxpc3RlbmVyXG4gICAgICAgIC8vIHRoYXQgY29udHJvbHMgYWNjZXNzIHRvIHRoaXMgc3RhdGUuIFJlZmVyIHRvIGFwcC5qcy5cbiAgICAgICAgZGF0YToge1xuICAgICAgICAgICAgYXV0aGVudGljYXRlOiB0cnVlXG4gICAgICAgIH1cbiAgICB9KTtcblxufSk7XG5cbmFwcC5mYWN0b3J5KCdTZWNyZXRTdGFzaCcsIGZ1bmN0aW9uICgkaHR0cCkge1xuXG4gICAgdmFyIGdldFN0YXNoID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL21lbWJlcnMvc2VjcmV0LXN0YXNoJykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5kYXRhO1xuICAgICAgICB9KTtcbiAgICB9O1xuXG4gICAgcmV0dXJuIHtcbiAgICAgICAgZ2V0U3Rhc2g6IGdldFN0YXNoXG4gICAgfTtcblxufSk7IiwiJ3VzZSBzdHJpY3QnO1xuXG5hcHAuZGlyZWN0aXZlKCdvYXV0aEJ1dHRvbicsIGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIHtcbiAgICBzY29wZToge1xuICAgICAgcHJvdmlkZXJOYW1lOiAnQCdcbiAgICB9LFxuICAgIHJlc3RyaWN0OiAnRScsXG4gICAgdGVtcGxhdGVVcmw6ICcvanMvb2F1dGgvb2F1dGgtYnV0dG9uLmh0bWwnXG4gIH1cbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdzaWdudXAnLCB7XG4gICAgICAgIHVybDogJy9zaWdudXAnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3NpZ251cC9zaWdudXAuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdTaWdudXBDdHJsJ1xuICAgIH0pO1xuXG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ1NpZ251cEN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBBdXRoU2VydmljZSwgJHN0YXRlKSB7XG5cbiAgICAkc2NvcGUuc2lnbnVwID0ge307XG4gICAgJHNjb3BlLmVycm9yID0gbnVsbDtcblxuICAgICRzY29wZS5zZW5kU2lnbnVwID0gZnVuY3Rpb24gKHNpZ251cEluZm8pIHtcbiAgICAgICAgJHNjb3BlLmVycm9yID0gbnVsbDtcbiAgICAgICAgQXV0aFNlcnZpY2Uuc2lnbnVwKHNpZ251cEluZm8pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKCdob21lJyk7XG4gICAgICAgIH0pLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICRzY29wZS5lcnJvciA9ICdPb3BzLCBjYW5ub3Qgc2lnbiB1cCB3aXRoIHRob3NlIGNyZWRlbnRpYWxzLic7XG4gICAgICAgIH0pO1xuXG4gICAgfTtcblxufSk7XG4iLCJhcHAuY29udHJvbGxlcignZGVsZXRlREJDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHVpYk1vZGFsLCAkbG9nKSB7XG5cbiAgJHNjb3BlLml0ZW1zID0gWydpdGVtMScsICdpdGVtMicsICdpdGVtMyddO1xuXG4gICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9IHRydWU7XG5cbiAgJHNjb3BlLm9wZW4gPSBmdW5jdGlvbiAoc2l6ZSkge1xuXG4gICAgdmFyIG1vZGFsSW5zdGFuY2UgPSAkdWliTW9kYWwub3Blbih7XG4gICAgICBhbmltYXRpb246ICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCxcbiAgICAgIHRlbXBsYXRlVXJsOiAnZGVsZXRlREJDb250ZW50Lmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ2RlbGV0ZURCSW5zdGFuY2VDdHJsJyxcbiAgICAgIHNpemU6IHNpemUsXG4gICAgICByZXNvbHZlOiB7XG4gICAgICAgIGl0ZW1zOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgcmV0dXJuICRzY29wZS5pdGVtcztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbiAoc2VsZWN0ZWRJdGVtKSB7XG4gICAgICAkc2NvcGUuc2VsZWN0ZWQgPSBzZWxlY3RlZEl0ZW07XG4gICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgJGxvZy5pbmZvKCdNb2RhbCBkaXNtaXNzZWQgYXQ6ICcgKyBuZXcgRGF0ZSgpKTtcbiAgICB9KTtcbiAgfTtcblxuICAkc2NvcGUudG9nZ2xlQW5pbWF0aW9uID0gZnVuY3Rpb24gKCkge1xuICAgICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9ICEkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQ7XG4gIH07XG5cbn0pO1xuXG5hcHAuY29udHJvbGxlcignZGVsZXRlREJJbnN0YW5jZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCAkdWliTW9kYWxJbnN0YW5jZSwgaXRlbXMsIFRhYmxlRmFjdG9yeSwgSG9tZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgJHN0YXRlKSB7XG5cblxuICAkc2NvcGUuZHJvcERiVGV4dCA9ICdEUk9QIERBVEFCQVNFJ1xuICAkc2NvcGUuZGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZTtcblxuICAkc2NvcGUuZGVsZXRlVGhlRGIgPSBmdW5jdGlvbigpe1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmNsb3NlKCRzY29wZS5zZWxlY3RlZC5pdGVtKTtcbiAgICBUYWJsZUZhY3RvcnkuZGVsZXRlRGIoJHNjb3BlLmRiTmFtZSlcbiAgICAudGhlbihmdW5jdGlvbigpe1xuICAgICAgSG9tZUZhY3RvcnkuZGVsZXRlREIoJHNjb3BlLmRiTmFtZSlcbiAgICB9KVxuICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgJHN0YXRlLmdvKCdIb21lJywge30sIHtyZWxvYWQgOiB0cnVlfSlcbiAgICB9KVxuICB9XG5cbiAgJHNjb3BlLml0ZW1zID0gaXRlbXM7XG4gICRzY29wZS5zZWxlY3RlZCA9IHtcbiAgICBpdGVtOiAkc2NvcGUuaXRlbXNbMF1cbiAgfTtcblxuICAkc2NvcGUub2sgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoJHNjb3BlLnNlbGVjdGVkLml0ZW0pO1xuICB9O1xuXG4gICRzY29wZS5jYW5jZWwgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuZGlzbWlzcygnY2FuY2VsJyk7XG4gIH07XG59KTsiLCJhcHAuY29udHJvbGxlcignRGVsZXRlRGJDdHJsJywgZnVuY3Rpb24gKCRzY29wZSkge1xuXG4gICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9IHRydWU7XG5cbiAgJHNjb3BlLm9wZW4gPSBmdW5jdGlvbiAoc2l6ZSkge1xuXG4gICAgdmFyIG1vZGFsSW5zdGFuY2UgPSAkdWliTW9kYWwub3Blbih7XG4gICAgICBhbmltYXRpb246ICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCxcbiAgICAgIHRlbXBsYXRlVXJsOiAnZGVsZXRlRGJDb250ZW50Lmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0RlbGV0ZURiSW5zdGFuY2VDdHJsJyxcbiAgICAgIHNpemU6IHNpemUsXG4gICAgICByZXNvbHZlOiB7XG4gICAgICAgIGl0ZW1zOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgcmV0dXJuICRzY29wZS5pdGVtcztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbiAoc2VsZWN0ZWRJdGVtKSB7XG4gICAgICAkc2NvcGUuc2VsZWN0ZWQgPSBzZWxlY3RlZEl0ZW07XG4gICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgJGxvZy5pbmZvKCdNb2RhbCBkaXNtaXNzZWQgYXQ6ICcgKyBuZXcgRGF0ZSgpKTtcbiAgICB9KTtcbiAgfTtcblxufSk7XG5cblxuYXBwLmNvbnRyb2xsZXIoJ0RlbGV0ZURiSW5zdGFuY2VDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHVpYk1vZGFsSW5zdGFuY2UsIGl0ZW1zLCAkc3RhdGVQYXJhbXMsIFRhYmxlRmFjdG9yeSkge1xuXG4gICRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lXG5cbiAgJHNjb3BlLmRyb3BEYXRhYmFzZSA9ICdEUk9QIERBVEFCQVNFJ1xuXG4gICRzY29wZS5kZWxldGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgVGFibGVGYWN0b3J5LmRlbGV0ZURiKCRzY29wZS5kYk5hbWUpXG4gICAgLy8gJHN0YXRlLmdvKCdIb21lJywge30sIHtyZWxvYWQgOiB0cnVlfSlcbiAgfTtcblxuICAkc2NvcGUuY2FuY2VsID0gZnVuY3Rpb24gKCkge1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmRpc21pc3MoJ2NhbmNlbCcpO1xuICB9O1xufSk7IiwiYXBwLmNvbnRyb2xsZXIoJ0pvaW5UYWJsZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgam9pblRhYmxlKSB7XG5cbiAgICAkc2NvcGUuam9pblRhYmxlID0gam9pblRhYmxlO1xuXG5cblx0ZnVuY3Rpb24gQ3JlYXRlQ29sdW1ucygpe1xuXHRcdCRzY29wZS5jb2x1bW5zID0gW107XG5cdFx0dmFyIHRhYmxlID0gJHNjb3BlLmpvaW5UYWJsZVswXTtcblxuXG5cdFx0Zm9yKHZhciBwcm9wIGluIHRhYmxlKXtcblx0XHRcdGlmKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpe1xuXHRcdFx0XHQkc2NvcGUuY29sdW1ucy5wdXNoKHByb3ApO1x0XG5cdFx0XHR9IFxuXHRcdH1cblx0fVxuXG4gICAgQ3JlYXRlQ29sdW1ucygpO1xuXG5cbiAgICAvL3RoaXMgZnVuY3Rpb24gd2lsbCByZSBydW4gd2hlbiB0aGUgZmlsdGVyIGZ1bmN0aW9uIGlzIGludm9rZWQsIGluIG9yZGVyIHRvIHJlcG9wdWxhdGUgdGhlIHRhYmxlXG4gICAgZnVuY3Rpb24gQ3JlYXRlUm93cygpIHtcbiAgICBcdHZhciBhbGlhcztcbiAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkgPSBbXTtcbiAgICAgICAgam9pblRhYmxlLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICB2YXIgcm93VmFsdWVzID0gW107XG4gICAgICAgICAgICBmb3IgKHZhciBwcm9wIGluIHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKSByb3dWYWx1ZXMucHVzaChyb3dbcHJvcF0pXG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheS5wdXNoKHJvd1ZhbHVlcylcbiAgICAgICAgfSlcbiAgICB9XG5cbiAgICAvLyBTb3J0IHRoZSB2YWx1ZXMgaW4gc2luZ2xlVGFibGUgc28gdGhhdCBhbGwgdGhlIHZhbHVlcyBmb3IgYSBnaXZlbiByb3cgYXJlIGdyb3VwZWRcbiAgICBDcmVhdGVSb3dzKCk7XG5cblxufSkiLCJhcHAuY29udHJvbGxlcignUXVlcnlUYWJsZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuXG5cblx0ZnVuY3Rpb24gQ3JlYXRlQ29sdW1ucygpe1xuXHRcdCRzY29wZS5jb2x1bW5zID0gW107XG5cdFx0dmFyIHRhYmxlID0gJHNjb3BlLmpvaW5UYWJsZVswXTtcblxuXG5cdFx0Zm9yKHZhciBwcm9wIGluIHRhYmxlKXtcblx0XHRcdGlmKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpe1xuXHRcdFx0XHQkc2NvcGUuY29sdW1ucy5wdXNoKHByb3ApO1x0XG5cdFx0XHR9IFxuXHRcdH1cblx0fVxuXG4gICAgQ3JlYXRlQ29sdW1ucygpO1xuXG5cbiAgICAvL3RoaXMgZnVuY3Rpb24gd2lsbCByZSBydW4gd2hlbiB0aGUgZmlsdGVyIGZ1bmN0aW9uIGlzIGludm9rZWQsIGluIG9yZGVyIHRvIHJlcG9wdWxhdGUgdGhlIHRhYmxlXG4gICAgZnVuY3Rpb24gQ3JlYXRlUm93cygpIHtcbiAgICBcdHZhciBhbGlhcztcbiAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkgPSBbXTtcbiAgICAgICAgam9pblRhYmxlLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICB2YXIgcm93VmFsdWVzID0gW107XG4gICAgICAgICAgICBmb3IgKHZhciBwcm9wIGluIHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKSByb3dWYWx1ZXMucHVzaChyb3dbcHJvcF0pXG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheS5wdXNoKHJvd1ZhbHVlcylcbiAgICAgICAgfSlcbiAgICB9XG5cbiAgICAvLyBTb3J0IHRoZSB2YWx1ZXMgaW4gc2luZ2xlVGFibGUgc28gdGhhdCBhbGwgdGhlIHZhbHVlcyBmb3IgYSBnaXZlbiByb3cgYXJlIGdyb3VwZWRcbiAgICBDcmVhdGVSb3dzKCk7XG5cblxufSkiLCJhcHAuY29udHJvbGxlcignU2luZ2xlVGFibGVDdHJsJywgZnVuY3Rpb24oJHNjb3BlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgc2luZ2xlVGFibGUsICR3aW5kb3csICRzdGF0ZSwgJHVpYk1vZGFsLCBhc3NvY2lhdGlvbnMpIHtcblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9QdXR0aW5nIHN0dWZmIG9uIHNjb3BlLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuXG4gICAgJHNjb3BlLnRoZURiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG4gICAgJHNjb3BlLnRoZVRhYmxlTmFtZSA9ICRzdGF0ZVBhcmFtcy50YWJsZU5hbWU7XG4gICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gc2luZ2xlVGFibGVbMF07XG4gICAgJHNjb3BlLnNlbGVjdGVkQWxsID0gZmFsc2U7XG4gICAgJHNjb3BlLmFzc29jaWF0aW9ucyA9IGFzc29jaWF0aW9ucztcblxuXG5cbiAgICBmdW5jdGlvbiBmb3JlaWduQ29sdW1uT2JqKCkge1xuICAgICAgICB2YXIgZm9yZWlnbkNvbHMgPSB7fTtcbiAgICAgICAgJHNjb3BlLmFzc29jaWF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgaWYgKHJvdy5UYWJsZTEgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgcm93LlJlbGF0aW9uc2hpcDEgPT09ICdoYXNPbmUnKSB7XG4gICAgICAgICAgICAgICAgZm9yZWlnbkNvbHNbcm93LkFsaWFzMV0gPSByb3cuVGFibGUyXG4gICAgICAgICAgICB9IGVsc2UgaWYgKHJvdy5UYWJsZTIgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgcm93LlJlbGF0aW9uc2hpcDIgPT09ICdoYXNPbmUnKSB7XG4gICAgICAgICAgICAgICAgZm9yZWlnbkNvbHNbcm93LkFsaWFzMl0gPSByb3cuVGFibGUxXG4gICAgICAgICAgICB9XG4gICAgICAgIH0pXG4gICAgICAgICRzY29wZS5mb3JlaWduQ29scyA9IGZvcmVpZ25Db2xzO1xuICAgIH1cblxuICAgIGZvcmVpZ25Db2x1bW5PYmooKTtcblxuXG4gICAgJHNjb3BlLmN1cnJlbnRUYWJsZSA9ICRzdGF0ZVBhcmFtcztcblxuICAgICRzY29wZS5teUluZGV4ID0gMTtcblxuICAgICRzY29wZS5pZHMgPSAkc2NvcGUuc2luZ2xlVGFibGUubWFwKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICByZXR1cm4gcm93LmlkO1xuICAgIH0pXG5cbiAgICAvL2RlbGV0ZSBhIHJvdyBcbiAgICAkc2NvcGUuc2hvd0RlbGV0ZSA9IGZhbHNlO1xuICAgICRzY29wZS50b2dnbGVEZWxldGUgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgJHNjb3BlLnNob3dEZWxldGUgPSAhJHNjb3BlLnNob3dEZWxldGVcbiAgICB9XG5cbiAgICAkc2NvcGUuZGVsZXRlU2VsZWN0ZWQgPSBmdW5jdGlvbihkYiwgdGFibGUsIGluc3RhbmNlQXJyYXkpIHtcbiAgICAgICAgaW5zdGFuY2VBcnJheS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgaWYgKHJvdy5zZWxlY3RlZCkge1xuICAgICAgICAgICAgICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVSb3coZGIsIHRhYmxlLCByb3dbJ3ZhbHVlcyddWzBdWyd2YWx1ZSddKVxuICAgICAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHJlc3VsdDtcbiAgICAgICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSlcbiAgICAgICAgJHNjb3BlLnNob3dEZWxldGUgPSBmYWxzZTtcbiAgICB9XG5cbiAgICAkc2NvcGUuc2VsZWN0QWxsID0gZnVuY3Rpb24oaW5zdGFuY2VBcnJheSkge1xuICAgICAgICBpZiAoJHNjb3BlLnNlbGVjdGVkQWxsKSB7XG4gICAgICAgICAgICBpbnN0YW5jZUFycmF5LmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICAgICAgcm93LnNlbGVjdGVkID0gdHJ1ZTtcbiAgICAgICAgICAgIH0pXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBpbnN0YW5jZUFycmF5LmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICAgICAgcm93LnNlbGVjdGVkID0gZmFsc2U7XG4gICAgICAgICAgICB9KVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLnVuY2hlY2tTZWxlY3RBbGwgPSBmdW5jdGlvbihpbnN0YW5jZUFycmF5KSB7XG4gICAgICAgIGlmICgkc2NvcGUuc2VsZWN0ZWRBbGwgPT09IHRydWUpIHtcbiAgICAgICAgICAgICRzY29wZS5zZWxlY3RlZEFsbCA9IGZhbHNlO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLnJlbW92ZVJvdyA9IGZ1bmN0aW9uKGRiLCB0YWJsZSwgcm93KSB7XG4gICAgICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVSb3coZGIsIHRhYmxlLCByb3cpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgfSlcbiAgICB9XG5cbiAgICAkc2NvcGUucmVtb3ZlQ29sdW1uID0gZnVuY3Rpb24oZGIsIHRhYmxlLCBjb2x1bW5OYW1lKSB7XG4gICAgICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVDb2x1bW4oZGIsIHRhYmxlLCBjb2x1bW5OYW1lKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0O1xuICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICBDcmVhdGVDb2x1bW5zKCk7XG4gICAgICAgICAgICB9KVxuICAgIH1cblxuICAgICRzY29wZS5uZXdSb3cgPSBmdW5jdGlvbihkYiwgdGFibGUsIGFycikge1xuICAgICAgICB2YXIgYWxsSWRzID0gW107XG4gICAgICAgIGFyci5mb3JFYWNoKGZ1bmN0aW9uKHJvd0RhdGEpIHtcbiAgICAgICAgICAgIGFsbElkcy5wdXNoKHJvd0RhdGEudmFsdWVzWzBdLnZhbHVlKVxuICAgICAgICB9KVxuICAgICAgICB2YXIgc29ydGVkID0gYWxsSWRzLnNvcnQoZnVuY3Rpb24oYSwgYikge1xuICAgICAgICAgICAgcmV0dXJuIGIgLSBhXG4gICAgICAgIH0pXG4gICAgICAgIGlmIChzb3J0ZWQubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgVGFibGVGYWN0b3J5LmFkZFJvdyhkYiwgdGFibGUsIHNvcnRlZFswXSArIDEpXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHJlc3VsdDtcbiAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgIH0pXG5cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIFRhYmxlRmFjdG9yeS5hZGRSb3coZGIsIHRhYmxlLCAxKVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLmFkZENvbHVtbiA9IGZ1bmN0aW9uKGRiLCB0YWJsZSkge1xuICAgICAgICB2YXIgY29sTnVtcyA9ICRzY29wZS5jb2x1bW5zLmpvaW4oJyAnKS5tYXRjaCgvXFxkKy9nKTtcbiAgICAgICAgaWYgKGNvbE51bXMpIHtcbiAgICAgICAgICAgIHZhciBzb3J0ZWROdW1zID0gY29sTnVtcy5zb3J0KGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gYiAtIGFcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB2YXIgbnVtSW5OZXcgPSBOdW1iZXIoc29ydGVkTnVtc1swXSkgKyAxO1xuICAgICAgICAgICAgdmFyIG5hbWVOZXdDb2wgPSAnQ29sdW1uICcgKyBudW1Jbk5ldy50b1N0cmluZygpO1xuXG4gICAgICAgICAgICBUYWJsZUZhY3RvcnkuYWRkQ29sdW1uKGRiLCB0YWJsZSwgbmFtZU5ld0NvbClcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSgkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKVxuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24odGhlVGFibGUpIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gdGhlVGFibGVbMF07XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZUNvbHVtbnMoKTtcbiAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB2YXIgbmV4dENvbE51bSA9ICRzY29wZS5jb2x1bW5zLmxlbmd0aCArIDE7XG4gICAgICAgICAgICB2YXIgbmV3Q29sTmFtZSA9ICdDb2x1bW4gJyArIG5leHRDb2xOdW07XG4gICAgICAgICAgICBUYWJsZUZhY3RvcnkuYWRkQ29sdW1uKGRiLCB0YWJsZSwgJ0NvbHVtbiAxJylcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSgkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKVxuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24odGhlVGFibGUpIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gdGhlVGFibGVbMF07XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZUNvbHVtbnMoKTtcbiAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgIH1cblxuICAgIH1cblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9Pcmdhbml6aW5nIHN0dWZmIGludG8gYXJyYXlzLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuXG4gICAgLy8gR2V0IGFsbCBvZiB0aGUgY29sdW1ucyB0byBjcmVhdGUgdGhlIGNvbHVtbnMgb24gdGhlIGJvb3RzdHJhcCB0YWJsZVxuXG4gICAgZnVuY3Rpb24gQ3JlYXRlQ29sdW1ucygpIHtcbiAgICAgICAgJHNjb3BlLmNvbHVtbnMgPSBbXTtcbiAgICAgICAgJHNjb3BlLm9yaWdpbmFsQ29sVmFscyA9IFtdO1xuICAgICAgICB2YXIgdGFibGUgPSAkc2NvcGUuc2luZ2xlVGFibGVbMF07XG5cblxuICAgICAgICBmb3IgKHZhciBwcm9wIGluIHRhYmxlKSB7XG4gICAgICAgICAgICBpZiAocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jykge1xuICAgICAgICAgICAgICAgICRzY29wZS5jb2x1bW5zLnB1c2gocHJvcCk7XG4gICAgICAgICAgICAgICAgJHNjb3BlLm9yaWdpbmFsQ29sVmFscy5wdXNoKHByb3ApO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgQ3JlYXRlQ29sdW1ucygpO1xuXG4gICAgZnVuY3Rpb24gY3JlYXRlVmlydHVhbENvbHVtbnMoKSB7XG4gICAgICAgIGlmICgkc2NvcGUuYXNzb2NpYXRpb25zLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgICRzY29wZS52aXJ0dWFsQ29sdW1ucyA9IFtdO1xuICAgICAgICAgICAgJHNjb3BlLmFzc29jaWF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChyb3cuVGFibGUxID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmIHJvdy5SZWxhdGlvbnNoaXAxID09PSAnaGFzTWFueScpIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHZpcnR1YWwgPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5uYW1lID0gcm93LkFsaWFzMTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHJvdy5UaHJvdWdoKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLnRhYmxlID0gcm93LlRocm91Z2g7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLmNvbHVtbmtleSA9IHJvdy5BbGlhczE7XG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLnRhYmxlID0gcm93LlRhYmxlMjtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwuY29sdW1ua2V5ID0gcm93LkFsaWFzMjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAkc2NvcGUudmlydHVhbENvbHVtbnMucHVzaCh2aXJ0dWFsKTtcbiAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKHJvdy5UYWJsZTIgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgcm93LlJlbGF0aW9uc2hpcDIgPT09ICdoYXNNYW55Jykge1xuICAgICAgICAgICAgICAgICAgICB2YXIgdmlydHVhbCA9IHt9O1xuICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLm5hbWUgPSByb3cuQWxpYXMyO1xuICAgICAgICAgICAgICAgICAgICBpZiAocm93LlRocm91Z2gpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwudGFibGUgPSByb3cuVGhyb3VnaDtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwuY29sdW1ua2V5ID0gcm93LkFsaWFzMjtcbiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwudGFibGUgPSByb3cuVGFibGUxO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5jb2x1bW5rZXkgPSByb3cuQWxpYXMxO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS52aXJ0dWFsQ29sdW1ucy5wdXNoKHZpcnR1YWwpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBjcmVhdGVWaXJ0dWFsQ29sdW1ucygpO1xuXG4gICAgLy90aGlzIGZ1bmN0aW9uIHdpbGwgcmUgcnVuIHdoZW4gdGhlIGZpbHRlciBmdW5jdGlvbiBpcyBpbnZva2VkLCBpbiBvcmRlciB0byByZXBvcHVsYXRlIHRoZSB0YWJsZVxuICAgIGZ1bmN0aW9uIENyZWF0ZVJvd3MoKSB7XG4gICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5ID0gW107XG4gICAgICAgICRzY29wZS5zaW5nbGVUYWJsZS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgdmFyIHJvd1ZhbHVlcyA9IFtdO1xuICAgICAgICAgICAgdmFyIHJvd09iaiA9IHt9O1xuXG4gICAgICAgICAgICBmb3IgKHZhciBwcm9wIGluIHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKSByb3dWYWx1ZXMucHVzaCh7XG4gICAgICAgICAgICAgICAgICAgIGNvbDogcHJvcCxcbiAgICAgICAgICAgICAgICAgICAgdmFsdWU6IHJvd1twcm9wXVxuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByb3dPYmoudmFsdWVzID0gcm93VmFsdWVzO1xuICAgICAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkucHVzaChyb3dPYmopO1xuICAgICAgICB9KVxuICAgIH1cblxuICAgIC8vIFNvcnQgdGhlIHZhbHVlcyBpbiBzaW5nbGVUYWJsZSBzbyB0aGF0IGFsbCB0aGUgdmFsdWVzIGZvciBhIGdpdmVuIHJvdyBhcmUgZ3JvdXBlZFxuICAgIENyZWF0ZVJvd3MoKTtcbiAgICAvL3NlbmRzIHRoZSBmaWx0ZXJpbmcgcXVlcnkgYW5kIHRoZW4gcmUgcmVuZGVycyB0aGUgdGFibGUgd2l0aCBmaWx0ZXJlZCBkYXRhXG4gICAgJHNjb3BlLmZpbHRlciA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCBkYXRhKSB7XG4gICAgICAgIFRhYmxlRmFjdG9yeS5maWx0ZXIoZGJOYW1lLCB0YWJsZU5hbWUsIGRhdGEpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQuZGF0YTtcbiAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICB9KVxuICAgIH1cblxuXG4gICAgJHNjb3BlLmNoZWNrRm9yZWlnbiA9IGZ1bmN0aW9uKGNvbCkge1xuICAgICAgICByZXR1cm4gJHNjb3BlLmZvcmVpZ25Db2xzLmhhc093blByb3BlcnR5KGNvbCk7XG4gICAgfVxuXG4gICAgJHNjb3BlLmZpbmRQcmltYXJ5ID0gVGFibGVGYWN0b3J5LmZpbmRQcmltYXJ5O1xuXG4gICAgLy8qKioqKioqKioqKiogSW1wb3J0YW50ICoqKioqKioqKlxuICAgIC8vIE1ha2Ugc3VyZSB0byB1cGRhdGUgdGhlIHJvdyB2YWx1ZXMgQkVGT1JFIHRoZSBjb2x1bW4gbmFtZVxuICAgIC8vIFRoZSByb3dWYWxzVG9VcGRhdGUgYXJyYXkgc3RvcmVzIHRoZSB2YWx1ZXMgb2YgdGhlIE9SSUdJTkFMIGNvbHVtbiBuYW1lcyBzbyBpZiB0aGUgY29sdW1uIG5hbWUgaXMgdXBkYXRlZCBhZnRlciB0aGUgcm93IHZhbHVlLCB3ZSBzdGlsbCBoYXZlIHJlZmVyZW5jZSB0byB3aGljaCBjb2x1bW4gdGhlIHJvdyB2YWx1ZSByZWZlcmVuY2VzXG5cblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9VcGRhdGluZyBDb2x1bW4gU3R1ZmYvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG5cbiAgICAkc2NvcGUuY29sVmFsc1RvVXBkYXRlID0gW107XG5cbiAgICAkc2NvcGUudXBkYXRlQ29sdW1ucyA9IGZ1bmN0aW9uKG9sZCwgbmV3Q29sTmFtZSwgaSkge1xuICAgICAgICAkc2NvcGUuY29sdW1uc1tpXSA9IG5ld0NvbE5hbWU7XG5cbiAgICAgICAgdmFyIGNvbE9iaiA9IHsgb2xkVmFsOiAkc2NvcGUub3JpZ2luYWxDb2xWYWxzW2ldLCBuZXdWYWw6IG5ld0NvbE5hbWUgfTtcblxuICAgICAgICAvLyBpZiB0aGVyZSBpcyBub3RoaW5nIGluIHRoZSBhcnJheSB0byB1cGRhdGUsIHB1c2ggdGhlIHVwZGF0ZSBpbnRvIGl0XG4gICAgICAgIGlmICgkc2NvcGUuY29sVmFsc1RvVXBkYXRlLmxlbmd0aCA9PT0gMCkgeyAkc2NvcGUuY29sVmFsc1RvVXBkYXRlLnB1c2goY29sT2JqKTsgfSBlbHNlIHtcbiAgICAgICAgICAgIGZvciAodmFyIGUgPSAwOyBlIDwgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZS5sZW5ndGg7IGUrKykge1xuICAgICAgICAgICAgICAgIGlmICgkc2NvcGUuY29sVmFsc1RvVXBkYXRlW2VdLm9sZFZhbCA9PT0gY29sT2JqLm9sZFZhbCkge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuY29sVmFsc1RvVXBkYXRlW2VdID0gY29sT2JqO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZS5wdXNoKGNvbE9iaik7XG4gICAgICAgIH1cbiAgICAgICAgLy8gY2hlY2sgdG8gc2VlIGlmIHRoZSByb3cgaXMgYWxyZWFkeSBzY2hlZHVsZWQgdG8gYmUgdXBkYXRlZCwgaWYgaXQgaXMsIHRoZW4gdXBkYXRlIGl0IHdpdGggdGhlIG5ldyB0aGluZyB0byBiZSB1cGRhdGVkXG4gICAgfVxuXG4gICAgLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1VwZGF0aW5nIFJvdyBTdHVmZi8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgICRzY29wZS5yb3dWYWxzVG9VcGRhdGUgPSBbXTtcblxuICAgICRzY29wZS51cGRhdGVSb3cgPSBmdW5jdGlvbihvbGQsIG5ld0NlbGwsIHJvdywgaSwgail7XG4gICAgICAgIHZhciBjb2xzID0gJHNjb3BlLm9yaWdpbmFsQ29sVmFscztcbiAgICAgICAgdmFyIGZvdW5kID0gZmFsc2U7XG4gICAgICAgIHZhciBjb2xOYW1lID0gY29sc1tqXTtcbiAgICAgICAgZm9yKHZhciBrID0gMDsgayA8ICRzY29wZS5yb3dWYWxzVG9VcGRhdGUubGVuZ3RoOyBrKyspe1xuICAgICAgICAgICAgdmFyIG9iaiA9ICRzY29wZS5yb3dWYWxzVG9VcGRhdGVba107XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhvYmopXG4gICAgICAgICAgICBpZihvYmpbJ2lkJ10gPT09IGkpe1xuICAgICAgICAgICAgICAgIGZvdW5kID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICBpZihvYmpbY29sTmFtZV0pIG9ialtjb2xOYW1lXSA9IG5ld0NlbGw7XG4gICAgICAgICAgICAgICAgb2JqW2NvbE5hbWVdID0gbmV3Q2VsbDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBpZighZm91bmQpIHtcbiAgICAgICAgICAgIHZhciByb3dPYmogPSB7fTtcbiAgICAgICAgICAgIHJvd09ialsnaWQnXSA9IGk7XG4gICAgICAgICAgICByb3dPYmpbY29sTmFtZV0gPSBuZXdDZWxsO1xuICAgICAgICAgICAgJHNjb3BlLnJvd1ZhbHNUb1VwZGF0ZS5wdXNoKHJvd09iailcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS51cGRhdGVCYWNrZW5kID0gZnVuY3Rpb24oKSB7XG4gICAgICAgIHZhciBkYXRhID0geyByb3dzOiAkc2NvcGUucm93VmFsc1RvVXBkYXRlLCBjb2x1bW5zOiAkc2NvcGUuY29sVmFsc1RvVXBkYXRlIH1cbiAgICAgICAgVGFibGVGYWN0b3J5LnVwZGF0ZUJhY2tlbmQoJHNjb3BlLnRoZURiTmFtZSwgJHNjb3BlLnRoZVRhYmxlTmFtZSwgZGF0YSk7XG4gICAgfVxuXG5cbiAgICAkc2NvcGUuZGVsZXRlVGFibGUgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgVGFibGVGYWN0b3J5LmRlbGV0ZVRhYmxlKCRzY29wZS5jdXJyZW50VGFibGUpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAkc3RhdGUuZ28oJ1RhYmxlJywgeyBkYk5hbWU6ICRzY29wZS50aGVEYk5hbWUgfSwgeyByZWxvYWQ6IHRydWUgfSlcbiAgICAgICAgICAgIH0pXG4gICAgfVxuXG4gICAgLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1F1ZXJ5aW5nIFN0dWZmLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuXG4gICAgJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9ucyA9IFtdO1xuXG4gICAgJHNjb3BlLnRhYmxlc1RvUXVlcnkgPSBbXTtcblxuICAgIGFzc29jaWF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICBpZiAocm93LlRhYmxlMSA9PT0gJHNjb3BlLnRoZVRhYmxlTmFtZSAmJiAkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zLmluZGV4T2Yocm93LlRhYmxlMikgPT0gLTEpIHtcbiAgICAgICAgICAgICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMucHVzaChyb3cuVGFibGUyKTtcbiAgICAgICAgfSBlbHNlIGlmIChyb3cuVGFibGUyID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMuaW5kZXhPZihyb3cuVGFibGUxKSA9PSAtMSkge1xuICAgICAgICAgICAgJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9ucy5wdXNoKHJvdy5UYWJsZTEpO1xuICAgICAgICB9XG4gICAgfSlcblxuICAgICRzY29wZS5nZXRBc3NvY2lhdGVkID0gZnVuY3Rpb24odmFsKSB7XG4gICAgICAgIGlmICgkc2NvcGUudGFibGVzVG9RdWVyeS5pbmRleE9mKCRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnNbdmFsXSkgPT09IC0xKSB7XG4gICAgICAgICAgICAkc2NvcGUudGFibGVzVG9RdWVyeS5wdXNoKCRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnNbdmFsXSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHZhciBpID0gJHNjb3BlLnRhYmxlc1RvUXVlcnkuaW5kZXhPZigkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zW3ZhbF0pO1xuICAgICAgICAgICAgJHNjb3BlLnRhYmxlc1RvUXVlcnkuc3BsaWNlKGksIDEpXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAkc2NvcGUuY29sdW1uc0ZvclF1ZXJ5ID0gW107XG5cbiAgICAkc2NvcGUuZ2V0Q29sdW1uc0ZvclRhYmxlID0gZnVuY3Rpb24oKSB7XG4gICAgICAgIHZhciBwcm9taXNlc0ZvckNvbHVtbnMgPSBbXTtcbiAgICAgICAgJHNjb3BlLnRhYmxlc1RvUXVlcnkuZm9yRWFjaChmdW5jdGlvbih0YWJsZU5hbWUpIHtcbiAgICAgICAgICAgIHJldHVybiBwcm9taXNlc0ZvckNvbHVtbnMucHVzaChUYWJsZUZhY3RvcnkuZ2V0Q29sdW1uc0ZvclRhYmxlKCRzY29wZS50aGVEYk5hbWUsIHRhYmxlTmFtZSkpXG4gICAgICAgIH0pXG4gICAgICAgIFByb21pc2UuYWxsKHByb21pc2VzRm9yQ29sdW1ucylcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKGNvbHVtbnMpIHtcbiAgICAgICAgICAgICAgICBjb2x1bW5zLmZvckVhY2goZnVuY3Rpb24oY29sdW1uKSB7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5jb2x1bW5zRm9yUXVlcnkucHVzaChjb2x1bW4pO1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuJGV2YWxBc3luYygpXG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIH0pXG5cbiAgICB9XG5cbiAgICB2YXIgc2VsZWN0ZWRDb2x1bW5zID0ge307XG4gICAgdmFyIHF1ZXJ5VGFibGU7XG5cbiAgICAkc2NvcGUuZ2V0RGF0YUZyb21Db2x1bW5zID0gZnVuY3Rpb24odmFsKSB7XG4gICAgICAgIGlmKCFzZWxlY3RlZENvbHVtbnMpIHNlbGVjdGVkQ29sdW1ucyA9IFtdO1xuXG4gICAgICAgIHZhciBjb2x1bW5OYW1lID0gJHNjb3BlLmNvbHVtbnNGb3JRdWVyeVswXVsnY29sdW1ucyddW3ZhbC5pXTtcbiAgICAgICAgdmFyIHRhYmxlTmFtZSA9IHZhbC50YWJsZU5hbWVcbiAgICAgICAgcXVlcnlUYWJsZSA9IHRhYmxlTmFtZTtcblxuICAgICAgICBpZiAoIXNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdKSBzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXSA9IFtdO1xuICAgICAgICBpZiAoc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0uaW5kZXhPZihjb2x1bW5OYW1lKSAhPT0gLTEpIHtcbiAgICAgICAgICAgIHNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdLnNwbGljZShzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXS5pbmRleE9mKGNvbHVtbk5hbWUpLCAxKVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0ucHVzaChjb2x1bW5OYW1lKTtcbiAgICAgICAgfVxuICAgICAgICAkc2NvcGUuc2VsZWN0ZWRDb2x1bW5zID0gc2VsZWN0ZWRDb2x1bW5zO1xuICAgIH1cblxuXG4gICAgLy8gUnVubmluZyB0aGUgcXVlcnkgKyByZW5kZXJpbmcgdGhlIHF1ZXJ5XG4gICAgJHNjb3BlLnJlc3VsdE9mUXVlcnkgPSBbXTtcblxuICAgICRzY29wZS5xdWVyeVJlc3VsdDtcblxuICAgICRzY29wZS5hcnIgPSBbXTtcblxuXG4gICAgLy8gdGhlVGFibGVOYW1lXG5cbiAgICAkc2NvcGUucnVuSm9pbiA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAvLyBkYk5hbWUsIHRhYmxlMSwgYXJyYXlPZlRhYmxlcywgc2VsZWN0ZWRDb2x1bW5zLCBhc3NvY2lhdGlvbnNcbiAgICAgICAgdmFyIGNvbHVtbnNUb1JldHVybiA9ICRzY29wZS5jb2x1bW5zLm1hcChmdW5jdGlvbihjb2xOYW1lKXtcbiAgICAgICAgICAgIHJldHVybiAkc2NvcGUudGhlVGFibGVOYW1lICsgJy4nICsgY29sTmFtZTtcbiAgICAgICAgfSlcbiAgICAgICAgZm9yKHZhciBwcm9wIGluICRzY29wZS5zZWxlY3RlZENvbHVtbnMpe1xuICAgICAgICAgICAkc2NvcGUuc2VsZWN0ZWRDb2x1bW5zW3Byb3BdLmZvckVhY2goZnVuY3Rpb24oY29sKXtcbiAgICAgICAgICAgICAgICBjb2x1bW5zVG9SZXR1cm4ucHVzaChwcm9wICsgJy4nICsgY29sKVxuICAgICAgICAgICB9KVxuICAgICAgICB9XG4gICAgICAgIFRhYmxlRmFjdG9yeS5ydW5Kb2luKCRzY29wZS50aGVEYk5hbWUsICRzY29wZS50aGVUYWJsZU5hbWUsICRzY29wZS50YWJsZXNUb1F1ZXJ5LCAkc2NvcGUuc2VsZWN0ZWRDb2x1bW5zLCAkc2NvcGUuYXNzb2NpYXRpb25zLCBjb2x1bW5zVG9SZXR1cm4pXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihxdWVyeVJlc3VsdCkge1xuICAgICAgICAgICAgICAgICRzY29wZS5xdWVyeVJlc3VsdCA9IHF1ZXJ5UmVzdWx0O1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnVGFibGUuU2luZ2xlLnF1ZXJ5Jyk7XG4gICAgICAgICAgICB9KVxuICAgIH1cblxufSk7XG4iLCJhcHAuY29udHJvbGxlcignVGFibGVDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgYWxsVGFibGVzLCAkc3RhdGUsIFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zLCAkdWliTW9kYWwsIEhvbWVGYWN0b3J5LCBhc3NvY2lhdGlvbnMsIGFsbENvbHVtbnMpIHtcblxuXHQkc2NvcGUuYWxsVGFibGVzID0gYWxsVGFibGVzO1xuXG5cdCRzY29wZS5jb2x1bW5BcnJheSA9IFtdO1xuXG5cdCRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lXG5cblx0JHNjb3BlLmFzc29jaWF0aW9ucyA9IGFzc29jaWF0aW9ucztcblxuXHQkc2NvcGUuYWxsQ29sdW1ucyA9IGFsbENvbHVtbnM7XG5cblx0JHNjb3BlLmFzc29jaWF0aW9uVGFibGUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lICsgJ19hc3NvYyc7XG5cblx0JHNjb3BlLm51bVRhYmxlcyA9ICRzY29wZS5hbGxUYWJsZXMucm93cy5sZW5ndGg7XG5cblx0JHNjb3BlLmFkZCA9IGZ1bmN0aW9uKCkge1xuXHRcdCRzY29wZS5jb2x1bW5BcnJheS5wdXNoKCcxJyk7XG5cdH1cblxuXHQkc2NvcGUuJHN0YXRlID0gJHN0YXRlOyBcdC8vIHVzZWQgdG8gaGlkZSB0aGUgbGlzdCBvZiBhbGwgdGFibGVzIHdoZW4gaW4gc2luZ2xlIHRhYmxlIHN0YXRlXG5cblx0JHNjb3BlLmFzc29jaWF0aW9uVHlwZXMgPSBbJ2hhc09uZScsICdoYXNNYW55J107XG5cblx0JHNjb3BlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG5cblx0JHNjb3BlLm1ha2VBc3NvY2lhdGlvbnMgPSBmdW5jdGlvbihhc3NvY2lhdGlvbiwgZGJOYW1lKSB7XG5cdFx0VGFibGVGYWN0b3J5Lm1ha2VBc3NvY2lhdGlvbnMoYXNzb2NpYXRpb24sIGRiTmFtZSlcblx0XHQudGhlbihmdW5jdGlvbigpIHtcblx0XHRcdCRzdGF0ZS5nbygnVGFibGUnLCB7ZGJOYW1lIDogJHNjb3BlLmRiTmFtZX0sIHtyZWxvYWQ6dHJ1ZX0pO1xuXHRcdH0pXG5cdH0gXG5cblx0JHNjb3BlLndoZXJlYmV0d2VlbiA9IGZ1bmN0aW9uKGNvbmRpdGlvbikge1xuXHRcdGlmKGNvbmRpdGlvbiA9PT0gXCJXSEVSRSBCRVRXRUVOXCIgfHwgY29uZGl0aW9uID09PSBcIldIRVJFIE5PVCBCRVRXRUVOXCIpIHJldHVybiB0cnVlO1xuXHR9XG5cblx0JHNjb3BlLmNyZWF0ZVRhYmxlID0gZnVuY3Rpb24odGFibGUpe1xuXHRcdFRhYmxlRmFjdG9yeS5jcmVhdGVUYWJsZSh0YWJsZSlcblx0XHQudGhlbihmdW5jdGlvbigpe1xuXHRcdFx0JHN0YXRlLmdvKCdUYWJsZScsIHtkYk5hbWU6JHNjb3BlLmRiTmFtZX0pO1xuXHRcdH0pXG5cdH1cblxuXHQkc2NvcGUuY29sdW1uRGF0YVR5cGUgPSBmdW5jdGlvbigpIHtcblx0XHQkc2NvcGUuYWxsQ29sdW1ucy5mb3JFYWNoKGZ1bmN0aW9uKG9iaikge1xuXHRcdFx0aWYob2JqLnRhYmxlX25hbWUgPT09ICRzY29wZS5xdWVyeS50YWJsZTEgJiYgb2JqLmNvbHVtbl9uYW1lID09PSAkc2NvcGUucXVlcnkuY29sdW1uKSAkc2NvcGUudHlwZSA9IG9iai5kYXRhX3R5cGU7XG5cdFx0fSlcblx0fVxuXG5cdCRzY29wZS5zZWxlY3RlZEFzc29jID0ge307XG5cblx0Ly8gJHNjb3BlLmdldEFzc29jaWF0ZWQgPSBmdW5jdGlvbih0YWJsZU5hbWUpIHtcblx0Ly8gXHQkc2NvcGUuYXNzb2NpYXRpb25zLmZvckVhY2goZnVuY3Rpb24ocm93KXtcblx0Ly8gXHRcdGlmKCEkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdKXsgXG5cdC8vIFx0XHRcdCRzY29wZS5zZWxlY3RlZEFzc29jW3RhYmxlTmFtZV0gPSBbXTtcblx0Ly8gXHRcdH1cblx0Ly8gXHRcdGlmKHJvdy5UYWJsZTEgPT09IHRhYmxlTmFtZSAmJiAkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdLmluZGV4T2Yocm93LlRhYmxlMikgPT0gLTEpe1xuXHQvLyBcdFx0XHQkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdLnB1c2gocm93LlRhYmxlMik7XG5cdC8vIFx0XHR9XG5cdC8vIFx0XHRlbHNlIGlmKHJvdy5UYWJsZTIgPT09IHRhYmxlTmFtZSAmJiAkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdLmluZGV4T2Yocm93LlRhYmxlMSkgPT0gLTEpe1xuXHQvLyBcdFx0XHQkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdLnB1c2gocm93LlRhYmxlMSk7XHRcblx0Ly8gXHRcdH0gXG5cdC8vIFx0fSlcblx0Ly8gfVxuXG5cdC8vICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMgPSBbXTtcblxuXHQvLyBhc3NvY2lhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihyb3cpe1xuXHQvLyBcdGlmKHJvdy5UYWJsZTEgPT09IHRhYmxlTmFtZSAmJiAkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdLmluZGV4T2Yocm93LlRhYmxlMikgPT0gLTEpe1xuXHQvLyBcdFx0JHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9ucy5wdXNoKHJvdy5UYWJsZTIpO1xuXHQvLyBcdH1cblx0Ly8gXHRlbHNlIGlmKHJvdy5UYWJsZTIgPT09IHRhYmxlTmFtZSAmJiAkc2NvcGUuc2VsZWN0ZWRBc3NvY1t0YWJsZU5hbWVdLmluZGV4T2Yocm93LlRhYmxlMSkgPT0gLTEpe1xuXHQvLyBcdFx0JHNjb3BlLnNlbGVjdGVkQXNzb2NbdGFibGVOYW1lXS5wdXNoKHJvdy5UYWJsZTEpO1x0XG5cdC8vIFx0fSBcblx0Ly8gfSlcblxuXHQkc2NvcGUuc3VibWl0UXVlcnkgPSBUYWJsZUZhY3Rvcnkuc3VibWl0UXVlcnk7XG5cbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ1RhYmxlRmFjdG9yeScsIGZ1bmN0aW9uICgkaHR0cCwgJHN0YXRlUGFyYW1zKSB7XG5cblx0dmFyIFRhYmxlRmFjdG9yeSA9IHt9O1xuXG5cdGZ1bmN0aW9uIHJlc1RvRGF0YShyZXMpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5kYXRhO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRBbGxUYWJsZXMgPSBmdW5jdGlvbihkYk5hbWUpe1xuICAgIFx0cmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lKVxuICAgIFx0LnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldERiTmFtZSA9IGZ1bmN0aW9uKGRiTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvbWFzdGVyZGIvJyArIGRiTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5maWx0ZXIgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgZGF0YSkge1xuICAgICAgICByZXR1cm4gJGh0dHAucHV0KCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnL2ZpbHRlcicsIGRhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LnVwZGF0ZUJhY2tlbmQgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgZGF0YSkge1xuICAgICAgICByZXR1cm4gJGh0dHAucHV0KCdhcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSwgZGF0YSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuYWRkUm93ID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIHJvd051bWJlcikge1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnYXBpL2NsaWVudGRiL2FkZHJvdy8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lLCB7cm93TnVtYmVyOiByb3dOdW1iZXJ9KVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVSb3cgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgcm93SWQpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnLycgKyByb3dJZClcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVDb2x1bW4gPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgY29sdW1uTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSArICcvY29sdW1uLycgKyBjb2x1bW5OYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmFkZENvbHVtbiA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCBudW1OZXdDb2wpe1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnYXBpL2NsaWVudGRiL2FkZGNvbHVtbi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lICsgJy8nICsgbnVtTmV3Q29sKVxuICAgIH1cbiAgICBUYWJsZUZhY3RvcnkuY3JlYXRlVGFibGUgPSBmdW5jdGlvbih0YWJsZSl7XG4gICAgICAgIHRhYmxlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG4gICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL2NsaWVudGRiJywgdGFibGUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmRlbGV0ZVRhYmxlID0gZnVuY3Rpb24oY3VycmVudFRhYmxlKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvY2xpZW50ZGIvJyArIGN1cnJlbnRUYWJsZS5kYk5hbWUgKyAnLycgKyBjdXJyZW50VGFibGUudGFibGVOYW1lKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5tYWtlQXNzb2NpYXRpb25zID0gZnVuY3Rpb24oYXNzb2NpYXRpb24sIGRiTmFtZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy9hc3NvY2lhdGlvbicsIGFzc29jaWF0aW9uKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5kZWxldGVEYiA9IGZ1bmN0aW9uKGRiTmFtZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldEFzc29jaWF0aW9ucyA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvYXNzb2NpYXRpb250YWJsZS8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgICBUYWJsZUZhY3RvcnkuZ2V0QWxsQXNzb2NpYXRpb25zID0gZnVuY3Rpb24oZGJOYW1lKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvYWxsYXNzb2NpYXRpb25zLycgKyBkYk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldEFsbENvbHVtbnMgPSBmdW5jdGlvbihkYk5hbWUpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi9nZXRhbGxjb2x1bW5zLycgKyBkYk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldENvbHVtbnNGb3JUYWJsZSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi9jb2x1bW5zZm9ydGFibGUvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkucnVuSm9pbiA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGUxLCBhcnJheU9mVGFibGVzLCBzZWxlY3RlZENvbHVtbnMsIGFzc29jaWF0aW9ucywgY29sc1RvUmV0dXJuKSB7XG4gICAgICAgIHZhciBkYXRhID0ge307XG4gICAgICAgIGRhdGEuZGJOYW1lID0gZGJOYW1lO1xuICAgICAgICBkYXRhLnRhYmxlMiA9IGFycmF5T2ZUYWJsZXNbMF07XG4gICAgICAgIGRhdGEuYXJyYXlPZlRhYmxlcyA9IGFycmF5T2ZUYWJsZXM7XG4gICAgICAgIGRhdGEuc2VsZWN0ZWRDb2x1bW5zID0gc2VsZWN0ZWRDb2x1bW5zO1xuICAgICAgICBkYXRhLmNvbHNUb1JldHVybiA9IGNvbHNUb1JldHVybjtcblxuICAgICAgICAvLyBbaGFzTWFueSwgaGFzT25lLCBoYXNNYW55IHByaW1hcnkga2V5LCBoYXNPbmUgZm9yZ2VpbiBrZXldXG5cbiAgICAgICAgYXNzb2NpYXRpb25zLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICBpZihyb3cuVGFibGUxID09PSB0YWJsZTEgJiYgcm93LlRhYmxlMiA9PT0gZGF0YS50YWJsZTIpe1xuICAgICAgICAgICAgICAgIGRhdGEuYWxpYXMgPSByb3cuQWxpYXMxO1xuICAgICAgICAgICAgICAgIGlmKHJvdy5SZWxhdGlvbnNoaXAxID09PSAnaGFzT25lJyl7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUxID0gcm93LlRhYmxlMjtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTIgPSByb3cuVGFibGUxO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNle1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMSA9IHJvdy5UYWJsZTE7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUyID0gcm93LlRhYmxlMjsgICBcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIGlmKHJvdy5UYWJsZTEgPT09IGRhdGEudGFibGUyICYmIHJvdy5UYWJsZTIgPT09IHRhYmxlMSl7XG4gICAgICAgICAgICAgICAgZGF0YS5hbGlhcyA9IHJvdy5BbGlhczE7XG4gICAgICAgICAgICAgICAgaWYocm93LlJlbGF0aW9uc2hpcDEgPT09ICdoYXNNYW55Jyl7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUxID0gcm93LlRhYmxlMTtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTIgPSByb3cuVGFibGUyO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNle1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMSA9IHJvdy5UYWJsZTI7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUyID0gcm93LlRhYmxlMTsgICBcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pXG5cbiAgICAgICAgcmV0dXJuICRodHRwLnB1dCgnL2FwaS9jbGllbnRkYi9ydW5qb2luJywgZGF0YSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZ2V0UHJpbWFyeUtleXMgPSBmdW5jdGlvbihpZCwgZGJOYW1lLCB0YWJsZU5hbWUsIGNvbHVtbmtleSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSArICcvJyArIGlkICsgXCIvXCIgKyBjb2x1bW5rZXkpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmZpbmRQcmltYXJ5ID0gZnVuY3Rpb24oZGJOYW1lLCB0YmxOYW1lKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi9wcmltYXJ5LycrZGJOYW1lKycvJyt0YmxOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuXHRyZXR1cm4gVGFibGVGYWN0b3J5OyBcbn0pIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUnLCB7XG4gICAgICAgIHVybDogJy86ZGJOYW1lJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS90YWJsZS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1RhYmxlQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgXHRhbGxUYWJsZXM6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRBbGxUYWJsZXMoJHN0YXRlUGFyYW1zLmRiTmFtZSk7XG4gICAgICAgIFx0fSwgXG4gICAgICAgICAgICBhc3NvY2lhdGlvbnM6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRBbGxBc3NvY2lhdGlvbnMoJHN0YXRlUGFyYW1zLmRiTmFtZSk7XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgYWxsQ29sdW1uczogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldEFsbENvbHVtbnMoJHN0YXRlUGFyYW1zLmRiTmFtZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KTtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5TaW5nbGUnLCB7XG4gICAgICAgIHVybDogJy86dGFibGVOYW1lJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9zaW5nbGV0YWJsZS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1NpbmdsZVRhYmxlQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICAgIHNpbmdsZVRhYmxlOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0U2luZ2xlVGFibGUoJHN0YXRlUGFyYW1zLmRiTmFtZSwgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSk7XG4gICAgICAgICAgICB9LCBcbiAgICAgICAgICAgIGFzc29jaWF0aW9uczogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldEFzc29jaWF0aW9ucygkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pO1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlLkpvaW4nLCB7XG4gICAgICAgIHVybDogJy86dGFibGVOYW1lLzpyb3dJZC86a2V5L2pvaW4nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL2pvaW4uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdKb2luVGFibGVDdHJsJyxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICAgICAgam9pblRhYmxlOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0UHJpbWFyeUtleXMoJHN0YXRlUGFyYW1zLnJvd0lkLCAkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lLCAkc3RhdGVQYXJhbXMua2V5KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pO1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlLmNyZWF0ZScsIHtcbiAgICAgICAgdXJsOiAnL2NyZWF0ZXRhYmxlJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9jcmVhdGV0YWJsZS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1RhYmxlQ3RybCdcbiAgICB9KTtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5zZXRBc3NvY2lhdGlvbicsIHtcbiAgICAgICAgdXJsOiAnL3NldGFzc29jaWF0aW9uJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9zZXRhc3NvY2lhdGlvbi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1RhYmxlQ3RybCdcbiAgICB9KTtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5TaW5nbGUucXVlcnknLCB7XG4gICAgICAgIHVybDogJy9xdWVyeXJlc3VsdCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvcXVlcnkuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdTaW5nbGVUYWJsZUN0cmwnXG4gICAgfSk7ICAgICBcblxufSk7IiwiYXBwLmZhY3RvcnkoJ0Z1bGxzdGFja1BpY3MnLCBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIFtcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CN2dCWHVsQ0FBQVhRY0UuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vZmJjZG4tc3Bob3Rvcy1jLWEuYWthbWFpaGQubmV0L2hwaG90b3MtYWsteGFwMS90MzEuMC04LzEwODYyNDUxXzEwMjA1NjIyOTkwMzU5MjQxXzgwMjcxNjg4NDMzMTI4NDExMzdfby5qcGcnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0ItTEtVc2hJZ0FFeTlTSy5qcGcnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I3OS1YN29DTUFBa3c3eS5qcGcnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0ItVWo5Q09JSUFJRkFoMC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I2eUl5RmlDRUFBcWwxMi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFLVQ3NWxXQUFBbXFxSi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFdlpBZy1WQUFBazkzMi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFZ05NZU9YSUFJZkRoSy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFUXlJRE5XZ0FBdTYwQi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NDRjNUNVFXOEFFMmxHSi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NBZVZ3NVNXb0FBQUxzai5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NBYUpJUDdVa0FBbElHcy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NBUU93OWxXRUFBWTlGbC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0ItT1FiVnJDTUFBTndJTS5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I5Yl9lcndDWUFBd1JjSi5wbmc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I1UFRkdm5DY0FFQWw0eC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I0cXdDMGlDWUFBbFBHaC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0IyYjMzdlJJVUFBOW8xRC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0J3cEl3cjFJVUFBdk8yXy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0JzU3NlQU5DWUFFT2hMdy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NKNHZMZnVVd0FBZGE0TC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NJN3d6akVWRUFBT1BwUy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NJZEh2VDJVc0FBbm5IVi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NHQ2lQX1lXWUFBbzc1Vi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NJUzRKUElXSUFJMzdxdS5qcGc6bGFyZ2UnXG4gICAgXTtcbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ1JhbmRvbUdyZWV0aW5ncycsIGZ1bmN0aW9uICgpIHtcblxuICAgIHZhciBnZXRSYW5kb21Gcm9tQXJyYXkgPSBmdW5jdGlvbiAoYXJyKSB7XG4gICAgICAgIHJldHVybiBhcnJbTWF0aC5mbG9vcihNYXRoLnJhbmRvbSgpICogYXJyLmxlbmd0aCldO1xuICAgIH07XG5cbiAgICB2YXIgZ3JlZXRpbmdzID0gW1xuICAgICAgICAnSGVsbG8sIHdvcmxkIScsXG4gICAgICAgICdBdCBsb25nIGxhc3QsIEkgbGl2ZSEnLFxuICAgICAgICAnSGVsbG8sIHNpbXBsZSBodW1hbi4nLFxuICAgICAgICAnV2hhdCBhIGJlYXV0aWZ1bCBkYXkhJyxcbiAgICAgICAgJ0lcXCdtIGxpa2UgYW55IG90aGVyIHByb2plY3QsIGV4Y2VwdCB0aGF0IEkgYW0geW91cnMuIDopJyxcbiAgICAgICAgJ1RoaXMgZW1wdHkgc3RyaW5nIGlzIGZvciBMaW5kc2F5IExldmluZS4nLFxuICAgICAgICAn44GT44KT44Gr44Gh44Gv44CB44Om44O844K244O85qeY44CCJyxcbiAgICAgICAgJ1dlbGNvbWUuIFRvLiBXRUJTSVRFLicsXG4gICAgICAgICc6RCcsXG4gICAgICAgICdZZXMsIEkgdGhpbmsgd2VcXCd2ZSBtZXQgYmVmb3JlLicsXG4gICAgICAgICdHaW1tZSAzIG1pbnMuLi4gSSBqdXN0IGdyYWJiZWQgdGhpcyByZWFsbHkgZG9wZSBmcml0dGF0YScsXG4gICAgICAgICdJZiBDb29wZXIgY291bGQgb2ZmZXIgb25seSBvbmUgcGllY2Ugb2YgYWR2aWNlLCBpdCB3b3VsZCBiZSB0byBuZXZTUVVJUlJFTCEnLFxuICAgIF07XG5cbiAgICByZXR1cm4ge1xuICAgICAgICBncmVldGluZ3M6IGdyZWV0aW5ncyxcbiAgICAgICAgZ2V0UmFuZG9tR3JlZXRpbmc6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiBnZXRSYW5kb21Gcm9tQXJyYXkoZ3JlZXRpbmdzKTtcbiAgICAgICAgfVxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZSgnZnVsbHN0YWNrTG9nbycsIGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4ge1xuICAgICAgICByZXN0cmljdDogJ0UnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL2Z1bGxzdGFjay1sb2dvL2Z1bGxzdGFjay1sb2dvLmh0bWwnXG4gICAgfTtcbn0pOyIsImFwcC5kaXJlY3RpdmUoJ3NpZGViYXInLCBmdW5jdGlvbiAoJHJvb3RTY29wZSwgQXV0aFNlcnZpY2UsIEFVVEhfRVZFTlRTLCAkc3RhdGUpIHtcblxuICAgIHJldHVybiB7XG4gICAgICAgIHJlc3RyaWN0OiAnRScsXG4gICAgICAgIHNjb3BlOiB7fSxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9uYXZiYXIvbmF2YmFyLmh0bWwnLFxuICAgICAgICBsaW5rOiBmdW5jdGlvbiAoc2NvcGUpIHtcblxuICAgICAgICAgICAgc2NvcGUuaXRlbXMgPSBbXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ0hvbWUnLCBzdGF0ZTogJ2hvbWUnIH0sXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ0Fib3V0Jywgc3RhdGU6ICdhYm91dCcgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnRG9jdW1lbnRhdGlvbicsIHN0YXRlOiAnZG9jcycgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnTWVtYmVycyBPbmx5Jywgc3RhdGU6ICdtZW1iZXJzT25seScsIGF1dGg6IHRydWUgfVxuICAgICAgICAgICAgXTtcblxuICAgICAgICAgICAgc2NvcGUudXNlciA9IG51bGw7XG5cbiAgICAgICAgICAgIHNjb3BlLmlzTG9nZ2VkSW4gPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgc2NvcGUubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIEF1dGhTZXJ2aWNlLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnbGFuZGluZ1BhZ2UnKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHZhciBzZXRVc2VyID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpLnRoZW4oZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgICAgICAgICAgICAgc2NvcGUudXNlciA9IHVzZXI7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICB2YXIgcmVtb3ZlVXNlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBzY29wZS51c2VyID0gbnVsbDtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHNldFVzZXIoKTtcblxuICAgICAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMubG9naW5TdWNjZXNzLCBzZXRVc2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLmxvZ291dFN1Y2Nlc3MsIHJlbW92ZVVzZXIpO1xuICAgICAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsIHJlbW92ZVVzZXIpO1xuXG4gICAgICAgIH1cblxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZSgncmFuZG9HcmVldGluZycsIGZ1bmN0aW9uIChSYW5kb21HcmVldGluZ3MpIHtcblxuICAgIHJldHVybiB7XG4gICAgICAgIHJlc3RyaWN0OiAnRScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvY29tbW9uL2RpcmVjdGl2ZXMvcmFuZG8tZ3JlZXRpbmcvcmFuZG8tZ3JlZXRpbmcuaHRtbCcsXG4gICAgICAgIGxpbms6IGZ1bmN0aW9uIChzY29wZSkge1xuICAgICAgICAgICAgc2NvcGUuZ3JlZXRpbmcgPSBSYW5kb21HcmVldGluZ3MuZ2V0UmFuZG9tR3JlZXRpbmcoKTtcbiAgICAgICAgfVxuICAgIH07XG5cbn0pOyJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
