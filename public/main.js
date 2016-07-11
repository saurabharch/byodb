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
        $state.go('Home', {}, { reload: true });
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

    if ($scope.associations.length > 0) {
        if ($scope.associations[0]['Through'] === $stateParams.tableName) {
            $state.go('Table.Through', { dbName: $stateParams.dbName, tableName: $stateParams.tableName });
        }
    }

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
            console.log('QUERYRRESULT', queryResult);
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

    $scope.csv = function (table) {
        alasql("SELECT * INTO CSV('mydata.csv', {headers:true}) FROM ?", [table]);
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

    $scope.submitted = false;

    $scope.makeAssociations = function (association, dbName) {
        $scope.submitted = true;
        TableFactory.makeAssociations(association, dbName);
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

    $scope.submitQuery = TableFactory.submitQuery;

    $scope.assoctable = function (tableName) {
        return tableName === $stateParams.dbName + "_assoc";
    };
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

        console.log('DATA', data);

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

    TableFactory.updateJoinTable = function (dbName, tableName, id, newRow, tableToUpdate, columnName) {
        var data = {};
        data.dbName = dbName;
        data.tblName = tableName;
        data.rowId = id;
        data.newRow = newRow;
        data.tableToUpdate = tableToUpdate;
        data.columnName = columnName;

        return $http.put('/api/clientdb/updateJoinTable', data).then(resToData);
    };

    TableFactory.increment = function (dbName, tableName) {
        return $http.put('/api/clientdb/' + dbName + '/' + tableName + '/addrowonjoin').then(resToData);
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

    $stateProvider.state('Table.Through', {
        url: '/:tableName/through',
        templateUrl: 'js/table/through.html',
        controller: 'ThroughCtrl',
        resolve: {
            singleTable: function singleTable(TableFactory, $stateParams) {
                return TableFactory.getSingleTable($stateParams.dbName, $stateParams.tableName);
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
app.controller('ThroughCtrl', function ($scope, TableFactory, $stateParams, associations, singleTable, $uibModal) {

    $scope.associations = associations;
    $scope.twoTables = [];
    $scope.singleTable = singleTable[0];
    $scope.theDbName = $stateParams.dbName;
    $scope.tableName = $stateParams.tableName;

    function get2Tables() {
        $scope.associations.forEach(function (assoc) {
            if (assoc['Through'] === $stateParams.tableName) {
                $scope.twoTables.push(assoc['Table1']);
                $scope.twoTables.push(assoc['Table2']); //here - come back
            }
        });
    }

    get2Tables();

    function CreateColumns() {
        $scope.columns = [];
        var table = singleTable[0][0];
        for (var prop in table) {
            $scope.columns.push(prop);
        }
    }

    CreateColumns();

    //this function will re run when the filter function is invoked, in order to repopulate the table
    function CreateRows() {

        $scope.instanceArray = [];
        $scope.singleTable.forEach(function (row) {
            var rowValues = [];
            for (var prop in row) {
                rowValues.push(row[prop]);
            }
            $scope.instanceArray.push(rowValues);
        });
    }

    // Sort the values in singleTable so that all the values for a given row are grouped
    CreateRows();

    // $scope.animationsEnabled = true;

    $scope.open = function (dbName, tableName, index, row, _columnName) {
        console.log(dbName, tableName, index, row, _columnName);
        var _theTable = $scope.twoTables[index - 1];
        console.log('twoTables', $scope.twoTables);
        console.log('theTable', _theTable);

        var modalInstance = $uibModal.open({
            animation: $scope.animationsEnabled,
            templateUrl: 'js/table/through.modal.html',
            controller: 'ThroughModalCtrl',
            resolve: {
                theTable: function theTable(TableFactory) {
                    return TableFactory.getSingleTable(dbName, _theTable);
                },
                tableName: function tableName() {
                    return _theTable;
                },
                rowId: function rowId() {
                    return row;
                },
                columnName: function columnName() {
                    return _columnName;
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

    $scope.newRow = function (db, table) {
        TableFactory.increment(db, table).then(function (result) {
            console.log(result);
            $scope.instanceArray = result;
            $scope.$evalAsync();
        });
    };

    //delete a row
    $scope.showDelete = false;
    $scope.toggleDelete = function () {
        $scope.showDelete = !$scope.showDelete;
    };

    $scope.deleteSelected = function (db, table, instanceArray) {
        instanceArray.forEach(function (row) {
            if (row.selected) {
                TableFactory.removeRow(db, table, row[0]).then(function (result) {
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

    $scope.csv = function (table) {
        alasql("SELECT * INTO CSV('mydata.csv', {headers:true}) FROM ?", [table]);
    };
});

app.controller('ThroughModalCtrl', function ($scope, $uibModalInstance, TableFactory, HomeFactory, $stateParams, $state, theTable, tableName, rowId, columnName) {

    $scope.dbName = $stateParams.dbName;

    $scope.singleTable = theTable;

    $scope.tableName = tableName;

    $scope.rowId = rowId;

    $scope.columnName = columnName;

    $scope.setSelected = function () {

        $scope.currRow = this.row;
        // console.log('HERE', $scope.currRow);
    };

    // console.log($scope.singleTable[0])
    function CreateColumns() {
        $scope.columns = [];
        var table = $scope.singleTable[0][0];

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
        $scope.singleTable[0].forEach(function (row) {
            var rowValues = [];
            for (var prop in row) {
                if (prop !== 'created_at' && prop !== 'updated_at') rowValues.push(row[prop]);
            }
            $scope.instanceArray.push(rowValues);
        });
    }

    // Sort the values in singleTable so that all the values for a given row are grouped
    CreateRows();

    $scope.setForeignKey = function (dbName, tblName, rowId, newRow) {
        $uibModalInstance.close();
        console.log('HERE', $scope.columnName);
        console.log(dbName, tblName, rowId, newRow, $stateParams.tableName);
        TableFactory.updateJoinTable(dbName, tblName, rowId, newRow, $stateParams.tableName, $scope.columnName);
        // .then(function() {
        //     // $state.go('Table.Single', { dbName: $scope.dbName, tableName: $scope.singleTable }, { reload: true })
        // })
    };

    $scope.ok = function () {
        $uibModalInstance.close($scope.selected.item);
    };

    $scope.cancel = function () {
        $uibModalInstance.dismiss('cancel');
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcC5qcyIsImFib3V0L2Fib3V0LmpzIiwiY3JlYXRlREIvY3JlYXRlREIuY29udHJvbGxlci5qcyIsImNyZWF0ZURCL2NyZWF0ZURCLmZhY3RvcnkuanMiLCJjcmVhdGVEQi9jcmVhdGVEQi5zdGF0ZS5qcyIsImRvY3MvZG9jcy5qcyIsImZzYS9mc2EtcHJlLWJ1aWx0LmpzIiwiaG9tZS9ob21lLmNvbnRyb2xsZXIuanMiLCJob21lL2hvbWUuZmFjdG9yeS5qcyIsImhvbWUvaG9tZS5zdGF0ZS5qcyIsImxhbmRpbmdQYWdlL2xhbmRpbmdQYWdlLnN0YXRlLmpzIiwibG9naW4vbG9naW4uanMiLCJtZW1iZXJzLW9ubHkvbWVtYmVycy1vbmx5LmpzIiwib2F1dGgvb2F1dGgtYnV0dG9uLmRpcmVjdGl2ZS5qcyIsInRhYmxlL2Fzc29jaWF0aW9uLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS9kZWxldGVEQk1vZGFsLmpzIiwidGFibGUvZGVsZXRlVGFibGVNb2RhbC5qcyIsInRhYmxlL2pvaW4uY29udHJvbGxlci5qcyIsInRhYmxlL3F1ZXJ5LmNvbnRyb2xsZXIuanMiLCJ0YWJsZS9zaW5nbGV0YWJsZS5jb250cm9sbGVyLmpzIiwidGFibGUvdGFibGUuY29udHJvbGxlci5qcyIsInRhYmxlL3RhYmxlLmZhY3RvcnkuanMiLCJ0YWJsZS90YWJsZS5zdGF0ZS5qcyIsInRhYmxlL3Rocm91Z2guY29udHJvbGxlci5qcyIsInRhYmxlL3Rocm91Z2hNb2RhbC5jb250cm9sbGVyLmpzIiwic2lnbnVwL3NpZ251cC5qcyIsImNvbW1vbi9mYWN0b3JpZXMvRnVsbHN0YWNrUGljcy5qcyIsImNvbW1vbi9mYWN0b3JpZXMvUmFuZG9tR3JlZXRpbmdzLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvZnVsbHN0YWNrLWxvZ28vZnVsbHN0YWNrLWxvZ28uanMiLCJjb21tb24vZGlyZWN0aXZlcy9uYXZiYXIvbmF2YmFyLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvcmFuZG8tZ3JlZXRpbmcvcmFuZG8tZ3JlZXRpbmcuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7O0FBQ0EsT0FBQSxHQUFBLEdBQUEsUUFBQSxNQUFBLENBQUEsdUJBQUEsRUFBQSxDQUFBLGFBQUEsRUFBQSxXQUFBLEVBQUEsY0FBQSxFQUFBLFdBQUEsQ0FBQSxDQUFBOztBQUVBLElBQUEsTUFBQSxDQUFBLFVBQUEsa0JBQUEsRUFBQSxpQkFBQSxFQUFBOztBQUVBLHNCQUFBLFNBQUEsQ0FBQSxJQUFBOztBQUVBLHVCQUFBLFNBQUEsQ0FBQSxHQUFBOztBQUVBLHVCQUFBLElBQUEsQ0FBQSxpQkFBQSxFQUFBLFlBQUE7QUFDQSxlQUFBLFFBQUEsQ0FBQSxNQUFBO0FBQ0EsS0FGQTtBQUdBLENBVEE7OztBQVlBLElBQUEsR0FBQSxDQUFBLFVBQUEsVUFBQSxFQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7OztBQUdBLFFBQUEsK0JBQUEsU0FBQSw0QkFBQSxDQUFBLEtBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxJQUFBLElBQUEsTUFBQSxJQUFBLENBQUEsWUFBQTtBQUNBLEtBRkE7Ozs7QUFNQSxlQUFBLEdBQUEsQ0FBQSxtQkFBQSxFQUFBLFVBQUEsS0FBQSxFQUFBLE9BQUEsRUFBQSxRQUFBLEVBQUE7O0FBRUEsWUFBQSxDQUFBLDZCQUFBLE9BQUEsQ0FBQSxFQUFBOzs7QUFHQTtBQUNBOztBQUVBLFlBQUEsWUFBQSxlQUFBLEVBQUEsRUFBQTs7O0FBR0E7QUFDQTs7O0FBR0EsY0FBQSxjQUFBOztBQUVBLG9CQUFBLGVBQUEsR0FBQSxJQUFBLENBQUEsVUFBQSxJQUFBLEVBQUE7Ozs7QUFJQSxnQkFBQSxJQUFBLEVBQUE7QUFDQSx1QkFBQSxFQUFBLENBQUEsUUFBQSxJQUFBLEVBQUEsUUFBQTtBQUNBLGFBRkEsTUFFQTtBQUNBLHVCQUFBLEVBQUEsQ0FBQSxPQUFBO0FBQ0E7QUFDQSxTQVRBO0FBV0EsS0E1QkE7QUE4QkEsQ0F2Q0E7O0FDZkEsSUFBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7OztBQUdBLG1CQUFBLEtBQUEsQ0FBQSxPQUFBLEVBQUE7QUFDQSxhQUFBLFFBREE7QUFFQSxvQkFBQSxpQkFGQTtBQUdBLHFCQUFBO0FBSEEsS0FBQTtBQU1BLENBVEE7O0FBV0EsSUFBQSxVQUFBLENBQUEsaUJBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxhQUFBLEVBQUE7OztBQUdBLFdBQUEsTUFBQSxHQUFBLEVBQUEsT0FBQSxDQUFBLGFBQUEsQ0FBQTtBQUVBLENBTEE7QUNYQSxJQUFBLFVBQUEsQ0FBQSxjQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBLGVBQUEsRUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxLQUFBO0FBQ0EsV0FBQSxXQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLEdBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxXQUFBLENBQUEsSUFBQSxDQUFBLEdBQUE7QUFDQSxLQUZBOztBQUlBLFdBQUEsUUFBQSxHQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0Esd0JBQUEsUUFBQSxDQUFBLElBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxJQUFBLEVBQUE7QUFDQSxtQkFBQSxTQUFBLEdBQUEsSUFBQTtBQUNBLFNBSEE7QUFJQSxLQUxBOztBQU9BLFdBQUEsV0FBQSxHQUFBLFVBQUEsS0FBQSxFQUFBLEVBQUEsRUFBQTtBQUNBLHdCQUFBLFdBQUEsQ0FBQSxLQUFBLEVBQUEsRUFBQTtBQUNBLGVBQUEsRUFBQSxDQUFBLE9BQUEsRUFBQSxFQUFBLFFBQUEsT0FBQSxTQUFBLENBQUEsTUFBQSxFQUFBLEVBQUEsRUFBQSxRQUFBLElBQUEsRUFBQTtBQUNBLEtBSEE7QUFJQSxDQXBCQTs7QUNBQSxJQUFBLE9BQUEsQ0FBQSxpQkFBQSxFQUFBLFVBQUEsS0FBQSxFQUFBOztBQUVBLFFBQUEsa0JBQUEsRUFBQTs7QUFFQSxhQUFBLFNBQUEsQ0FBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLElBQUEsSUFBQTtBQUNBOztBQUVBLG9CQUFBLFFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxJ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QUEsR0FBQSxDQUFBLE9BQUEsT0FBQTtBQUNBLEtBSkE7O0FBUUEsYUFBQSxhQUFBLEdBQUE7QUFDQSxlQUFBLE9BQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxRQUFBLFNBQUEsQ0FBQSxDQUFBOztBQUdBLGFBQUEsSUFBQSxJQUFBLElBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxPQUFBLENBQUEsSUFBQSxDQUFBLElBQUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7OztBQUlBLGFBQUEsVUFBQSxHQUFBO0FBQ0EsZUFBQSxhQUFBLEdBQUEsRUFBQTtBQUNBLGlCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLFlBQUEsRUFBQTtBQUNBLGlCQUFBLElBQUEsSUFBQSxJQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBLFVBQUEsSUFBQSxDQUFBLElBQUEsSUFBQSxDQUFBO0FBQ0E7QUFDQSxtQkFBQSxhQUFBLENBQUEsSUFBQSxDQUFBLFNBQUE7QUFDQSxTQU5BO0FBT0E7OztBQUdBOztBQUdBLFdBQUEsYUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLE9BQUEsRUFBQSxPQUFBLEVBQUEsR0FBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLDBCQUFBLEtBQUE7QUFDQSxxQkFBQSxhQUFBLENBQUEsTUFBQSxFQUFBLE9BQUEsRUFBQSxPQUFBLEVBQUEsR0FBQSxFQUFBLEdBQUEsRUFDQSxJQURBLENBQ0EsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxjQUFBLEVBQUEsRUFBQSxRQUFBLE9BQUEsTUFBQSxFQUFBLFdBQUEsT0FBQSxTQUFBLEVBQUEsRUFBQSxFQUFBLFFBQUEsSUFBQSxFQUFBO0FBQ0EsU0FIQTtBQUlBLEtBTkE7O0FBVUEsV0FBQSxFQUFBLEdBQUEsWUFBQTtBQUNBLDBCQUFBLEtBQUEsQ0FBQSxPQUFBLFFBQUEsQ0FBQSxJQUFBO0FBQ0EsS0FGQTs7QUFJQSxX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QUFBLElBQUEsQ0FBQSxTQUFBO0FBQ0EsU0FOQTtBQU9BOzs7QUFHQTtBQUdBLENBckNBO0FDQUEsSUFBQSxVQUFBLENBQUEsZ0JBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBOztBQUVBLFdBQUEsT0FBQSxHQUFBLFVBQUEsZUFBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsQ0FBQSxlQUFBLEVBQUEsT0FBQSxJQUFBLENBQUEsS0FDQTtBQUNBLGlCQUFBLElBQUEsSUFBQSxJQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFVBQUEsSUFBQSxJQUFBLEVBQUEsUUFBQSxHQUFBLFdBQUEsRUFBQTtBQUNBLG9CQUFBLFlBQUEsZ0JBQUEsUUFBQSxHQUFBLFdBQUEsRUFBQTtBQUNBLHdCQUFBLEdBQUEsQ0FBQSxPQUFBLEVBQUEsU0FBQSxFQUFBLFFBQUEsT0FBQSxDQUFBLFNBQUEsTUFBQSxDQUFBLENBQUE7QUFDQSxvQkFBQSxRQUFBLE9BQUEsQ0FBQSxTQUFBLE1BQUEsQ0FBQSxDQUFBLEVBQUEsT0FBQSxJQUFBO0FBQ0E7QUFDQTtBQUNBLGVBQUEsS0FBQTtBQUNBLEtBWEE7QUFhQSxDQWZBO0FDQUEsSUFBQSxVQUFBLENBQUEsaUJBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBLFdBQUEsRUFBQSxPQUFBLEVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxZQUFBLEVBQUEsSUFBQSxFQUFBOzs7O0FBSUEsV0FBQSxTQUFBLEdBQUEsYUFBQSxNQUFBO0FBQ0EsV0FBQSxZQUFBLEdBQUEsYUFBQSxTQUFBO0FBQ0EsV0FBQSxXQUFBLEdBQUEsWUFBQSxDQUFBLEVBQUEsSUFBQSxDQUFBLFVBQUEsQ0FBQSxFQUFBLENBQUEsRUFBQTtBQUNBLFlBQUEsRUFBQSxFQUFBLEdBQUEsRUFBQSxFQUFBLEVBQUEsT0FBQSxDQUFBO0FBQ0EsWUFBQSxFQUFBLEVBQUEsR0FBQSxFQUFBLEVBQUEsRUFBQSxPQUFBLENBQUEsQ0FBQTtBQUNBLGVBQUEsQ0FBQTtBQUNBLEtBSkEsQ0FBQTtBQUtBLFdBQUEsV0FBQSxHQUFBLEtBQUE7QUFDQSxXQUFBLFlBQUEsR0FBQSxZQUFBOztBQUdBLFFBQUEsT0FBQSxZQUFBLENBQUEsTUFBQSxHQUFBLENBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxZQUFBLENBQUEsQ0FBQSxFQUFBLFNBQUEsTUFBQSxhQUFBLFNBQUEsRUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxlQUFBLEVBQUEsRUFBQSxRQUFBLGFBQUEsTUFBQSxFQUFBLFdBQUEsYUFBQSxTQUFBLEVBQUE7QUFDQTtBQUNBOztBQUdBLGFBQUEsZ0JBQUEsR0FBQTtBQUNBLFlBQUEsY0FBQSxFQUFBO0FBQ0EsZUFBQSxZQUFBLENBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxNQUFBLEtBQUEsT0FBQSxZQUFBLElBQUEsSUFBQSxhQUFBLEtBQUEsUUFBQSxFQUFBO0FBQ0EsNEJBQUEsSUFBQSxNQUFBLElBQUEsSUFBQSxNQUFBO0FBQ0EsYUFGQSxNQUVBLElBQUEsSUFBQSxNQUFBLEtBQUEsT0FBQSxZQUFBLElBQUEsSUFBQSxhQUFBLEtBQUEsUUFBQSxFQUFBO0FBQ0EsNEJBQUEsSUFBQSxNQUFBLElBQUEsSUFBQSxNQUFBO0FBQ0E7QUFDQSxTQU5BO0FBT0EsZUFBQSxXQUFBLEdBQUEsV0FBQTtBQUNBOztBQUVBOztBQUdBLFdBQUEsWUFBQSxHQUFBLFlBQUE7O0FBRUEsV0FBQSxPQUFBLEdBQUEsQ0FBQTs7QUFFQSxXQUFBLEdBQUEsR0FBQSxPQUFBLFdBQUEsQ0FBQSxHQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLElBQUEsRUFBQTtBQUNBLEtBRkEsQ0FBQTs7O0FBS0EsV0FBQSxVQUFBLEdBQUEsS0FBQTtBQUNBLFdBQUEsWUFBQSxHQUFBLFlBQUE7QUFDQSxlQUFBLFVBQUEsR0FBQSxDQUFBLE9BQUEsVUFBQTtBQUNBLEtBRkE7O0FBSUEsV0FBQSxjQUFBLEdBQUEsVUFBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLGFBQUEsRUFBQTtBQUNBLGFBQUEsSUFBQSxJQUFBLGNBQUEsTUFBQSxHQUFBLENBQUEsRUFBQSxLQUFBLENBQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxNQUFBLGNBQUEsQ0FBQSxDQUFBO0FBQ0EsZ0JBQUEsU0FBQSxDQUFBO0FBQ0Esb0JBQUEsR0FBQSxDQUFBLEdBQUE7QUFDQSxnQkFBQSxJQUFBLFFBQUEsRUFBQTtBQUNBLDZCQUFBLFNBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLElBQUEsUUFBQSxFQUFBLENBQUEsRUFBQSxPQUFBLENBQUEsRUFBQSxNQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsMkJBQUEsV0FBQSxHQUFBLE1BQUE7QUFDQTtBQUNBLGlCQUpBO0FBS0E7QUFDQTtBQUNBLGVBQUEsVUFBQSxHQUFBLEtBQUE7QUFDQSxLQWRBOztBQWdCQSxXQUFBLFNBQUEsR0FBQSxVQUFBLGFBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxXQUFBLEVBQUE7QUFDQSwwQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxRQUFBLEdBQUEsSUFBQTtBQUNBLGFBRkE7QUFHQSxTQUpBLE1BSUE7QUFDQSwwQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxRQUFBLEdBQUEsS0FBQTtBQUNBLGFBRkE7QUFHQTtBQUNBLEtBVkE7O0FBWUEsV0FBQSxnQkFBQSxHQUFBLFVBQUEsYUFBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLFdBQUEsS0FBQSxJQUFBLEVBQUE7QUFDQSxtQkFBQSxXQUFBLEdBQUEsS0FBQTtBQUNBO0FBQ0EsS0FKQTs7QUFNQSxXQUFBLFNBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsR0FBQSxFQUFBLGFBQUEsRUFBQTtBQUNBLFlBQUEsU0FBQSxjQUFBLE1BQUEsR0FBQSxDQUFBO0FBQ0EscUJBQUEsU0FBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsR0FBQSxFQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSxtQkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsU0FKQTtBQUtBLEtBUEE7O0FBU0EsV0FBQSxZQUFBLEdBQUEsVUFBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLFVBQUEsRUFBQTtBQUNBLHFCQUFBLFlBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLFVBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSxtQkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0E7QUFDQSxTQUxBO0FBTUEsS0FQQTs7QUFTQSxXQUFBLE1BQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxTQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsQ0FBQSxVQUFBLE9BQUEsRUFBQTtBQUNBLG1CQUFBLElBQUEsQ0FBQSxRQUFBLE1BQUEsQ0FBQSxDQUFBLEVBQUEsS0FBQTtBQUNBLFNBRkE7QUFHQSxZQUFBLFNBQUEsT0FBQSxJQUFBLENBQUEsVUFBQSxDQUFBLEVBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBO0FBQ0EsU0FGQSxDQUFBO0FBR0EsWUFBQSxPQUFBLE1BQUEsR0FBQSxDQUFBLEVBQUE7QUFDQSx5QkFBQSxNQUFBLENBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxPQUFBLENBQUEsSUFBQSxDQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsdUJBQUEsV0FBQSxHQUFBLE1BQUE7QUFDQTtBQUNBLGFBSkE7QUFNQSxTQVBBLE1BT0E7QUFDQSx5QkFBQSxNQUFBLENBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxDQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsdUJBQUEsV0FBQSxHQUFBLE1BQUE7QUFDQTtBQUNBLGFBSkE7QUFLQTtBQUNBLEtBdEJBOztBQXdCQSxXQUFBLFNBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUE7QUFDQSxZQUFBLFVBQUEsT0FBQSxPQUFBLENBQUEsSUFBQSxDQUFBLEdBQUEsRUFBQSxLQUFBLENBQUEsTUFBQSxDQUFBO0FBQ0EsWUFBQSxPQUFBLEVBQUE7QUFDQSxnQkFBQSxhQUFBLFFBQUEsSUFBQSxDQUFBLFVBQUEsQ0FBQSxFQUFBLENBQUEsRUFBQTtBQUNBLHVCQUFBLElBQUEsQ0FBQTtBQUNBLGFBRkEsQ0FBQTtBQUdBLGdCQUFBLFdBQUEsT0FBQSxXQUFBLENBQUEsQ0FBQSxJQUFBLENBQUE7QUFDQSxnQkFBQSxhQUFBLFlBQUEsU0FBQSxRQUFBLEVBQUE7O0FBRUEseUJBQUEsU0FBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUNBLElBREEsQ0FDQSxZQUFBO0FBQ0EsdUJBQUEsYUFBQSxjQUFBLENBQUEsYUFBQSxNQUFBLEVBQUEsYUFBQSxTQUFBLENBQUE7QUFDQSxhQUhBLEVBSUEsSUFKQSxDQUlBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsdUJBQUEsV0FBQSxHQUFBLFNBQUEsQ0FBQSxDQUFBO0FBQ0E7QUFDQTtBQUNBLGFBUkE7QUFTQSxTQWhCQSxNQWdCQTtBQUNBLGdCQUFBLGFBQUEsT0FBQSxPQUFBLENBQUEsTUFBQSxHQUFBLENBQUE7QUFDQSxnQkFBQSxhQUFBLFlBQUEsVUFBQTtBQUNBLHlCQUFBLFNBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLFVBQUEsRUFDQSxJQURBLENBQ0EsWUFBQTtBQUNBLHVCQUFBLGFBQUEsY0FBQSxDQUFBLGFBQUEsTUFBQSxFQUFBLGFBQUEsU0FBQSxDQUFBO0FBQ0EsYUFIQSxFQUlBLElBSkEsQ0FJQSxVQUFBLFFBQUEsRUFBQTtBQUNBLHVCQUFBLFdBQUEsR0FBQSxTQUFBLENBQUEsQ0FBQTtBQUNBO0FBQ0E7QUFDQSxhQVJBO0FBU0E7QUFFQSxLQWhDQTs7Ozs7O0FBc0NBLGFBQUEsYUFBQSxHQUFBO0FBQ0EsZUFBQSxPQUFBLEdBQUEsRUFBQTtBQUNBLGVBQUEsZUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLFFBQUEsT0FBQSxXQUFBLENBQUEsQ0FBQSxDQUFBOztBQUdBLGFBQUEsSUFBQSxJQUFBLElBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxPQUFBLENBQUEsSUFBQSxDQUFBLElBQUE7QUFDQSx1QkFBQSxlQUFBLENBQUEsSUFBQSxDQUFBLElBQUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7O0FBRUEsYUFBQSxvQkFBQSxHQUFBO0FBQ0EsWUFBQSxPQUFBLFlBQUEsQ0FBQSxNQUFBLEdBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsY0FBQSxHQUFBLEVBQUE7QUFDQSxtQkFBQSxZQUFBLENBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsSUFBQSxNQUFBLEtBQUEsT0FBQSxZQUFBLElBQUEsSUFBQSxhQUFBLEtBQUEsU0FBQSxFQUFBO0FBQ0Esd0JBQUEsVUFBQSxFQUFBO0FBQ0EsNEJBQUEsSUFBQSxHQUFBLElBQUEsTUFBQTtBQUNBLHdCQUFBLElBQUEsT0FBQSxFQUFBO0FBQ0EsZ0NBQUEsS0FBQSxHQUFBLElBQUEsT0FBQTtBQUNBLGdDQUFBLFNBQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSxxQkFIQSxNQUdBO0FBQ0EsZ0NBQUEsS0FBQSxHQUFBLElBQUEsTUFBQTtBQUNBLGdDQUFBLFNBQUEsR0FBQSxJQUFBLE1BQUE7QUFDQTtBQUNBLDJCQUFBLGNBQUEsQ0FBQSxJQUFBLENBQUEsT0FBQTtBQUNBLGlCQVhBLE1BV0EsSUFBQSxJQUFBLE1BQUEsS0FBQSxPQUFBLFlBQUEsSUFBQSxJQUFBLGFBQUEsS0FBQSxTQUFBLEVBQUE7QUFDQSx3QkFBQSxVQUFBLEVBQUE7QUFDQSw0QkFBQSxJQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0Esd0JBQUEsSUFBQSxPQUFBLEVBQUE7QUFDQSxnQ0FBQSxLQUFBLEdBQUEsSUFBQSxPQUFBO0FBQ0EsZ0NBQUEsU0FBQSxHQUFBLElBQUEsTUFBQTtBQUNBLHFCQUhBLE1BR0E7QUFDQSxnQ0FBQSxLQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EsZ0NBQUEsU0FBQSxHQUFBLElBQUEsTUFBQTtBQUNBO0FBQ0EsMkJBQUEsY0FBQSxDQUFBLElBQUEsQ0FBQSxPQUFBO0FBQ0E7QUFDQSxhQXhCQTtBQXlCQTtBQUNBOztBQUVBOzs7QUFHQSxhQUFBLFVBQUEsR0FBQTtBQUNBLGVBQUEsYUFBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLFdBQUEsQ0FBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxZQUFBLEVBQUE7QUFDQSxnQkFBQSxTQUFBLEVBQUE7O0FBRUEsaUJBQUEsSUFBQSxJQUFBLElBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUEsVUFBQSxJQUFBLENBQUE7QUFDQSx5QkFBQSxJQURBO0FBRUEsMkJBQUEsSUFBQSxJQUFBO0FBRkEsaUJBQUE7QUFJQTtBQUNBLG1CQUFBLE1BQUEsR0FBQSxTQUFBO0FBQ0EsbUJBQUEsYUFBQSxDQUFBLElBQUEsQ0FBQSxNQUFBO0FBQ0EsU0FaQTtBQWFBOzs7QUFHQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsSUFBQSxFQUFBO0FBQ0EscUJBQUEsTUFBQSxDQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsSUFBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE1BQUEsRUFBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxPQUFBLElBQUE7QUFDQTtBQUNBLFNBSkE7QUFLQSxLQU5BOztBQVNBLFdBQUEsWUFBQSxHQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZUFBQSxPQUFBLFdBQUEsQ0FBQSxjQUFBLENBQUEsR0FBQSxDQUFBO0FBQ0EsS0FGQTs7QUFJQSxXQUFBLFdBQUEsR0FBQSxhQUFBLFdBQUE7Ozs7Ozs7O0FBU0EsV0FBQSxlQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLGFBQUEsR0FBQSxVQUFBLEdBQUEsRUFBQSxVQUFBLEVBQUEsQ0FBQSxFQUFBO0FBQ0EsZUFBQSxPQUFBLENBQUEsQ0FBQSxJQUFBLFVBQUE7O0FBRUEsWUFBQSxTQUFBLEVBQUEsUUFBQSxPQUFBLGVBQUEsQ0FBQSxDQUFBLENBQUEsRUFBQSxRQUFBLFVBQUEsRUFBQTs7O0FBR0EsWUFBQSxPQUFBLGVBQUEsQ0FBQSxNQUFBLEtBQUEsQ0FBQSxFQUFBO0FBQUEsbUJBQUEsZUFBQSxDQUFBLElBQUEsQ0FBQSxNQUFBO0FBQUEsU0FBQSxNQUFBO0FBQ0EsaUJBQUEsSUFBQSxJQUFBLENBQUEsRUFBQSxJQUFBLE9BQUEsZUFBQSxDQUFBLE1BQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxPQUFBLGVBQUEsQ0FBQSxDQUFBLEVBQUEsTUFBQSxLQUFBLE9BQUEsTUFBQSxFQUFBO0FBQ0EsMkJBQUEsZUFBQSxDQUFBLENBQUEsSUFBQSxNQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsbUJBQUEsZUFBQSxDQUFBLElBQUEsQ0FBQSxNQUFBO0FBQ0E7O0FBRUEsS0FoQkE7Ozs7QUFvQkEsV0FBQSxlQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxVQUFBLEdBQUEsRUFBQSxPQUFBLEVBQUEsR0FBQSxFQUFBLENBQUEsRUFBQSxDQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsT0FBQSxlQUFBO0FBQ0EsWUFBQSxRQUFBLEtBQUE7QUFDQSxZQUFBLFVBQUEsS0FBQSxDQUFBLENBQUE7QUFDQSxhQUFBLElBQUEsSUFBQSxDQUFBLEVBQUEsSUFBQSxPQUFBLGVBQUEsQ0FBQSxNQUFBLEVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsTUFBQSxPQUFBLGVBQUEsQ0FBQSxDQUFBLENBQUE7QUFDQSxvQkFBQSxHQUFBLENBQUEsR0FBQTtBQUNBLGdCQUFBLElBQUEsSUFBQSxNQUFBLENBQUEsRUFBQTtBQUNBLHdCQUFBLElBQUE7QUFDQSxvQkFBQSxJQUFBLE9BQUEsQ0FBQSxFQUFBLElBQUEsT0FBQSxJQUFBLE9BQUE7QUFDQSxvQkFBQSxPQUFBLElBQUEsT0FBQTtBQUNBO0FBQ0E7QUFDQSxZQUFBLENBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JB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LE9BQUEsVUFBQTtBQUNBLFlBQUEsTUFBQSxRQUFBLE9BQUEsVUFBQTtBQUNBLGVBQUEsWUFBQSxHQUFBLE9BQUEsYUFBQSxDQUFBLEtBQUEsQ0FBQSxLQUFBLEVBQUEsR0FBQSxDQUFBO0FBQ0EsS0FKQTs7QUFNQSxXQUFBLE1BQUEsQ0FBQSxlQUFBLEVBQUEsWUFBQTtBQUNBLFlBQUEsUUFBQSxDQUFBLE9BQUEsV0FBQSxHQUFBLENBQUEsSUFBQSxPQUFBLFVBQUE7QUFDQSxZQUFBLE1BQUEsUUFBQSxPQUFBLFVBQUE7QUFDQSxlQUFBLFlBQUEsR0FBQSxPQUFBLGFBQUEsQ0FBQSxLQUFBLENBQUEsS0FBQSxFQUFBLEdBQUEsQ0FBQTtBQUNBLEtBSkE7O0FBTUEsV0FBQSxHQUFBLEdBQUEsVUFBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLHdEQUFBLEVBQUEsQ0FBQSxLQUFBLENBQUE7QUFDQSxLQUZBO0FBSUEsQ0FwZEE7O0FDQUEsSUFBQSxVQUFBLENBQUEsV0FBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxNQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQSxTQUFBLEVBQUEsV0FBQSxFQUFBLFlBQUEsRUFBQSxVQUFBLEVBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsU0FBQTs7QUFFQSxXQUFBLFdBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsTUFBQSxHQUFBLGFBQUEsTUFBQTs7QUFFQSxXQUFBLFlBQUEsR0FBQSxZQUFBOztBQUVBLFdBQUEsVUFBQSxHQUFBLFVBQUE7O0FBRUEsV0FBQSxnQkFBQSxHQUFBLGFBQUEsTUFBQSxHQUFBLFFBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsT0FBQSxTQUFBLENBQUEsSUFBQSxDQUFBLE1BQUE7O0FBRUEsV0FBQSxHQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsV0FBQSxDQUFBLElBQUEsQ0FBQSxHQUFBO0FBQ0EsS0FGQTs7QUFJQSxXQUFBLE1BQUEsR0FBQSxNQUFBLEM7O0FBRUEsV0FBQSxnQkFBQSxHQUFBLENBQUEsUUFBQSxFQUFBLFNBQUEsQ0FBQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxhQUFBLE1BQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsS0FBQTs7QUFFQSxXQUFBLGdCQUFBLEdBQUEsVUFBQSxXQUFBLEVBQUEsTUFBQSxFQUFBO0FBQ0EsZUFBQSxTQUFBLEdBQUEsSUFBQTtBQUNBLHFCQUFBLGdCQUFBLENBQUEsV0FBQSxFQUFBLE1BQUE7QUFDQSxLQUhBOztBQUtBLFdBQUEsWUFBQSxHQUFBLFVBQUEsU0FBQSxFQUFBO0FBQ0EsWUFBQSxjQUFBLGVBQUEsSUFBQSxjQUFBLG1CQUFBLEVBQUEsT0FBQSxJQUFBO0FBQ0EsS0FGQTs7QUFJQSxXQUFBLFdBQUEsR0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLHFCQUFBLFdBQUEsQ0FBQSxLQUFBLEVBQ0EsSUFEQSxDQUNBLFlBQUE7QUFDQSxtQkFBQSxFQUFBLENBQUEsT0FBQSxFQUFBLEVBQUEsUUFBQSxPQUFBLE1BQUEsRUFBQSxFQUFBLEVBQUEsUUFBQSxJQUFBLEVBQUE7QUFDQSxTQUhBO0FBSUEsS0FMQTs7QUFPQSxXQUFBLGNBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxVQUFBLENBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxVQUFBLEtBQUEsT0FBQSxLQUFBLENBQUEsTUFBQSxJQUFBLElBQUEsV0FBQSxLQUFBLE9BQUEsS0FBQSxDQUFBLE1BQUEsRUFBQSxPQUFBLElBQUEsR0FBQSxJQUFBLFNBQUE7QUFDQSxTQUZBO0FBR0EsS0FKQTs7QUFNQSxXQUFBLGFBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsV0FBQSxHQUFBLGFBQUEsV0FBQTs7QUFFQSxXQUFBLFVBQUEsR0FBQSxVQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsY0FBQSxhQUFBLE1BQUEsR0FBQSxRQUFBO0FBQ0EsS0FGQTtBQUlBLENBMURBOztBQ0FBLElBQUEsT0FBQSxDQUFBLGNBQUEsRUFBQSxVQUFBLEtBQUEsRUFBQSxZQUFBLEVBQUE7O0FBRUEsUUFBQSxlQUFBLEVBQUE7O0FBRUEsYUFBQSxTQUFBLENBQUEsR0FBQSxFQUFBO0FBQ0EsZUFBQSxJQUFBLElBQUE7QUFDQTs7QUFFQSxpQkFBQSxZQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1CQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxjQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxTQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1CQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxNQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLElBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEdBQUEsU0FBQSxFQUFBLElBQUEsQ0FBQTtBQUNBLEtBRkE7O0FBSUEsaUJBQUEsYUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxJQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLGtCQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxFQUFBLElBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxNQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxJQUFBLENBQUEseUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQUEsRUFBQSxXQUFBLFNBQUEsRUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFNBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsS0FBQSxFQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEdBQUEsR0FBQSxHQUFBLEtBQUEsR0FBQSxHQUFBLEdBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFlBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsVUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLE1BQUEsQ0FBQSxtQkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsR0FBQSxVQUFBLEdBQUEsVUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFNBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLElBQUEsQ0FBQSw0QkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxDQUFBO0FBQ0EsS0FGQTtBQUdBLGlCQUFBLFdBQUEsR0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLGNBQUEsTUFBQSxHQUFBLGFBQUEsTUFBQTtBQUNBLGVBQUEsTUFBQSxJQUFBLENBQUEsZUFBQSxFQUFBLEtBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FKQTs7QUFNQSxpQkFBQSxXQUFBLEdBQUEsVUFBQSxZQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsTUFBQSxDQUFBLG1CQUFBLGFBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxhQUFBLFNBQUEsQ0FBQTtBQUNBLEtBRkE7O0FBSUEsaUJBQUEsZ0JBQUEsR0FBQSxVQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxjQUFBLEVBQUEsV0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGVBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG9DQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGtCQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1DQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxhQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLGlDQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxrQkFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUNBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsT0FBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLE1BQUEsRUFBQSxhQUFBLEVBQUEsZUFBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsRUFBQTtBQUNBLGFBQUEsTUFBQSxHQUFBLE1BQUE7QUFDQSxhQUFBLE1BQUEsR0FBQSxjQUFBLENBQUEsQ0FBQTtBQUNBLGFBQUEsYUFBQSxHQUFBLGFBQUE7QUFDQSxhQUFBLGVBQUEsR0FBQSxlQUFBO0FBQ0EsYUFBQSxZQUFBLEdBQUEsWUFBQTs7OztBQUlBLHFCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLElBQUEsTUFBQSxLQUFBLE1BQUEsSUFBQSxJQUFBLE1BQUEsS0FBQSxLQUFBLE1BQUEsRUFBQTtBQUNBLHFCQUFBLEtBQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSxvQkFBQSxJQUFBLGFBQUEsS0FBQSxRQUFBLEVBQUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EseUJBQUEsTUFBQSxHQUFBLElBQUEsTUFBQTtBQUNBLGlCQUhBLE1BSUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EseUJBQUEsTUFBQSxHQUFBLElBQUEsTUFBQTtBQUNBO0FBQ0EsYUFWQSxNQVdBLElBQUEsSUFBQSxNQUFBLEtBQUEsS0FBQSxNQUFBLElBQUEsSUFBQSxNQUFBLEtBQUEsTUFBQSxFQUFBO0FBQ0EscUJBQUEsS0FBQSxHQUFBLElBQUEsTUFBQTtBQUNBLG9CQUFBLElBQUEsYUFBQSxLQUFBLFNBQUEsRUFBQTtBQUNBLHlCQUFBLE1BQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EsaUJBSEEsTUFJQTtBQUNBLHlCQUFBLE1BQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0E7QUFDQTtBQUNBLFNBdkJBOztBQXlCQSxnQkFBQSxHQUFBLENBQUEsTUFBQSxFQUFBLElBQUE7O0FBRUEsZUFBQSxNQUFBLEdBQUEsQ0FBQSx1QkFBQSxFQUFBLElBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0F2Q0E7O0FBeUNBLGlCQUFBLGNBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEdBQUEsR0FBQSxHQUFBLEVBQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFdBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxPQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLDJCQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsT0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxPQUFBLEVBQUEsT0FBQSxFQUFBLEdBQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsRUFBQTtBQUNBLGFBQUEsTUFBQSxHQUFBLE1BQUE7QUFDQSxhQUFBLE9BQUEsR0FBQSxPQUFBO0FBQ0EsYUFBQSxPQUFBLEdBQUEsT0FBQTtBQUNBLGFBQUEsR0FBQSxHQUFBLEdBQUE7QUFDQSxhQUFBLEdBQUEsR0FBQSxHQUFBOztBQUVBLGVBQUEsTUFBQSxHQUFBLENBQUEsNkJBQUEsRUFBQSxJQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBVkE7O0FBWUEsaUJBQUEsZUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxFQUFBLEVBQUEsTUFBQSxFQUFBLGFBQUEsRUFBQSxVQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsRUFBQTtBQUNBLGFBQUEsTUFBQSxHQUFBLE1BQUE7QUFDQSxhQUFBLE9BQUEsR0FBQSxTQUFBO0FBQ0EsYUFBQSxLQUFBLEdBQUEsRUFBQTtBQUNBLGFBQUEsTUFBQSxHQUFBLE1BQUE7QUFDQSxhQUFBLGFBQUEsR0FBQSxhQUFBO0FBQ0EsYUFBQSxVQUFBLEdBQUEsVUFBQTs7QUFFQSxlQUFBLE1BQUEsR0FBQSxDQUFBLCtCQUFBLEVBQUEsSUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQVhBOztBQWFBLGlCQUFBLFNBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxHQUFBLGVBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxXQUFBLFlBQUE7QUFDQSxDQTVLQTtBQ0FBLElBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0EsbUJBQUEsS0FBQSxDQUFBLE9BQUEsRUFBQTtBQUNBLGFBQUEsVUFEQTtBQUVBLHFCQUFBLHFCQUZBO0FBR0Esb0JBQUEsV0FIQTtBQUlBLGlCQUFBO0FBQ0EsdUJBQUEsbUJBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLGFBQUEsWUFBQSxDQUFBLGFBQUEsTUFBQSxDQUFBO0FBQ0EsYUFIQTtBQUlBLDBCQUFBLHNCQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxhQUFBLGtCQUFBLENBQUEsYUFBQSxNQUFBLENBQUE7QUFDQSxhQU5BO0FBT0Esd0JBQUEsb0JBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLGFBQUEsYUFBQSxDQUFBLGFBQUEsTUFBQSxDQUFBO0FBQ0E7QUFUQTtBQUpBLEtBQUE7O0FBaUJBLG1CQUFBLEtBQUEsQ0FBQSxjQUFBLEVBQUE7QUFDQSxhQUFBLGFBREE7QUFFQSxxQkFBQSwyQkFGQTtBQUdBLG9CQUFBLGlCQUhBO0FBSUEsaUJBQUE7QUFDQSx5QkFBQSxxQkFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsYUFBQSxjQUFBLENBQUEsYUFBQSxNQUFBLEVBQUEsYUFBQSxTQUFBLENBQUE7QUFDQSxhQUhBO0FBSUEsMEJBQUEsc0JBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLGFBQUEsZUFBQSxDQUFBLGFBQUEsTUFBQSxFQUFBLGFBQUEsU0FBQSxDQUFBO0FBQ0E7QUFOQTtBQUpBLEtBQUE7O0FBY0EsbUJBQUEsS0FBQSxDQUFBLFlBQUEsRUFBQTtBQUNBLGFBQUEsOEJBREE7QUFFQSxxQkFBQSxvQkFGQTtBQUdBLG9CQUFBLGVBSEE7QUFJQSxpQkFBQTtBQUNBLHVCQUFBLG1CQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxhQUFBLGNBQUEsQ0FBQSxhQUFBLEtBQUEsRUFBQSxhQUFBLE1BQUEsRUFBQSxhQUFBLFNBQUEsRUFBQSxhQUFBLEdBQUEsQ0FBQTtBQUNBO0FBSEE7QUFKQSxLQUFBOztBQVdBLG1CQUFBLEtBQUEsQ0FBQSxlQUFBLEVBQUE7QUFDQSxhQUFBLHFCQURBO0FBRUEscUJBQUEsdUJBRkE7QUFHQSxvQkFBQSxhQUhBO0FBSUEsaUJBQUE7QUFDQSx5QkFBQSxxQkFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsYUFBQSxjQUFBLENBQUEsYUFBQSxNQUFBLEVBQUEsYUFBQSxTQUFBLENBQUE7QUFDQTtBQUhBO0FBSkEsS0FBQTs7QUFXQSxtQkFBQSxLQUFBLENBQUEsY0FBQSxFQUFBO0FBQ0EsYUFBQSxjQURBO0FBRUEscUJBQUEsMkJBRkE7QUFHQSxvQkFBQTtBQUhBLEtBQUE7O0FBTUEsbUJBQUEsS0FBQSxDQUFBLHNCQUFBLEVBQUE7QUFDQSxhQUFBLGlCQURBO0FBRUEscUJBQUEsOEJBRkE7QUFHQSxvQkFBQTtBQUhBLEtBQUE7O0FBTUEsbUJBQUEsS0FBQSxDQUFBLG9CQUFBLEVBQUE7QUFDQSxhQUFBLGNBREE7QUFFQSxxQkFBQSxxQkFGQTtBQUdBLG9CQUFBO0FBSEEsS0FBQTtBQU9BLENBekVBO0FDQUEsSUFBQSxVQUFBLENBQUEsYUFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBLFdBQUEsRUFBQSxTQUFBLEVBQUE7O0FBRUEsV0FBQSxZQUFBLEdBQUEsWUFBQTtBQUNBLFdBQUEsU0FBQSxHQUFBLEVBQUE7QUFDQSxXQUFBLFdBQUEsR0FBQSxZQUFBLENBQUEsQ0FBQTtBQUNBLFdBQUEsU0FBQSxHQUFBLGFBQUEsTUFBQTtBQUNBLFdBQUEsU0FBQSxHQUFBLGFBQUEsU0FBQTs7QUFFQSxhQUFBLFVBQUEsR0FBQTtBQUNBLGVBQUEsWUFBQSxDQUFBLE9BQUEsQ0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLGdCQUFBLE1BQUEsU0FBQSxNQUFBLGFBQUEsU0FBQSxFQUFBO0FBQ0EsdUJBQUEsU0FBQSxDQUFBLElBQUEsQ0FBQSxNQUFBLFFBQUEsQ0FBQTtBQUNBLHVCQUFBLFNBQUEsQ0FBQSxJQUFBLENBQUEsTUFBQSxRQUFBLENBQUEsRTtBQUNBO0FBQ0EsU0FMQTtBQU1BOztBQUVBOztBQUVBLGFBQUEsYUFBQSxHQUFBO0FBQ0EsZUFBQSxPQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsUUFBQSxZQUFBLENBQUEsRUFBQSxDQUFBLENBQUE7QUFDQSxhQUFBLElBQUEsSUFBQSxJQUFBLEtBQUEsRUFBQTtBQUNBLG1CQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsSUFBQTtBQUNBO0FBQ0E7O0FBRUE7OztBQUlBLGFBQUEsVUFBQSxHQUFBOztBQUVBLGVBQUEsYUFBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLFdBQUEsQ0FBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxZQUFBLEVBQUE7QUFDQSxpQkFBQSxJQUFBLElBQUEsSUFBQSxHQUFBLEVBQUE7QUFDQSwwQkFBQSxJQUFBLENBQUEsSUFBQSxJQUFBLENBQUE7QUFDQTtBQUNBLG1CQUFBLGFBQUEsQ0FBQSxJQUFBLENBQUEsU0FBQTtBQUNBLFNBTkE7QUFPQTs7O0FBR0E7Ozs7QUFJQSxXQUFBLElBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsS0FBQSxFQUFBLEdBQUEsRUFBQSxXQUFBLEVBQUE7QUFDQSxnQkFBQSxHQUFBLENBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxLQUFBLEVBQUEsR0FBQSxFQUFBLFdBQUE7QUFDQSxZQUFBLFlBQUEsT0FBQSxTQUFBLENBQUEsUUFBQSxDQUFBLENBQUE7QUFDQSxnQkFBQSxHQUFBLENBQUEsV0FBQSxFQUFBLE9BQUEsU0FBQTtBQUNBLGdCQUFBLEdBQUEsQ0FBQSxVQUFBLEVBQUEsU0FBQTs7QUFFQSxZQUFBLGdCQUFBLFVBQUEsSUFBQSxDQUFBO0FBQ0EsdUJBQUEsT0FBQSxpQkFEQTtBQUVBLHlCQUFBLDZCQUZBO0FBR0Esd0JBQUEsa0JBSEE7QUFJQSxxQkFBQTtBQUNBLDBCQUFBLGtCQUFBLFlBQUEsRUFBQTtBQUNBLDJCQUFBLGFBQUEsY0FBQSxDQUFBLE1BQUEsRUFBQSxTQUFBLENBQUE7QUFDQSxpQkFIQTtBQUlBLDJCQUFBLHFCQUFBO0FBQUEsMkJBQUEsU0FBQTtBQUFBLGlCQUpBO0FBS0EsdUJBQUEsaUJBQUE7QUFBQSwyQkFBQSxHQUFBO0FBQUEsaUJBTEE7QUFNQSw0QkFBQSxzQkFBQTtBQUFBLDJCQUFBLFdBQUE7QUFBQTtBQU5BO0FBSkEsU0FBQSxDQUFBOztBQWNBLHNCQUFBLE1BQUEsQ0FBQSxJQUFBLENBQUEsWUFBQTtBQUNBLG9CQUFBLEdBQUEsQ0FBQSxRQUFBO0FBQ0EsbUJBQUEsVUFBQTtBQUNBLFNBSEE7QUFJQSxLQXhCQTs7QUEwQkEsV0FBQSxlQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsaUJBQUEsR0FBQSxDQUFBLE9BQUEsaUJBQUE7QUFDQSxLQUZBOztBQUlBLFdBQUEsTUFBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQTtBQUNBLHFCQUFBLFNBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE1BQUEsRUFBQTtBQUNBLG9CQUFBLEdBQUEsQ0FBQSxNQUFBO0FBQ0EsbUJBQUEsYUFBQSxHQUFBLE1BQUE7QUFDQSxtQkFBQSxVQUFBO0FBQ0EsU0FMQTtBQU1BLEtBUEE7OztBQVVBLFdBQUEsVUFBQSxHQUFBLEtBQUE7QUFDQSxXQUFBLFlBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxVQUFBLEdBQUEsQ0FBQSxPQUFBLFVBQUE7QUFDQSxLQUZBOztBQUlBLFdBQUEsY0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxhQUFBLEVBQUE7QUFDQSxzQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxJQUFBLFFBQUEsRUFBQTtBQUNBLDZCQUFBLFNBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLElBQUEsQ0FBQSxDQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsMkJBQUEsV0FBQSxHQUFBLE1BQUE7QUFDQTtBQUNBLGlCQUpBO0FBS0E7QUFDQSxTQVJBO0FBU0EsZUFBQSxVQUFBLEdBQUEsS0FBQTtBQUNBLEtBWEE7O0FBYUEsV0FBQSxTQUFBLEdBQUEsVUFBQSxhQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsV0FBQSxFQUFBO0FBQ0EsMEJBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsUUFBQSxHQUFBLElBQUE7QUFDQSxhQUZBO0FBR0EsU0FKQSxNQUlBO0FBQ0EsMEJBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsUUFBQSxHQUFBLEtBQUE7QUFDQSxhQUZBO0FBR0E7QUFDQSxLQVZBOztBQVlBLFdBQUEsZ0JBQUEsR0FBQSxVQUFBLGFBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxXQUFBLEtBQUEsSUFBQSxFQUFBO0FBQ0EsbUJBQUEsV0FBQSxHQUFBLEtBQUE7QUFDQTtBQUNBLEtBSkE7O0FBTUEsV0FBQSxTQUFBLEdBQUEsVUFBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLHFCQUFBLFNBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLEdBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSxtQkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsU0FKQTtBQUtBLEtBTkE7O0FBUUEsV0FBQSxHQUFBLEdBQUEsVUFBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLHdEQUFBLEVBQUEsQ0FBQSxLQUFBLENBQUE7QUFDQSxLQUZBO0FBSUEsQ0F4SUE7O0FDQUEsSUFBQSxVQUFBLENBQUEsa0JBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxpQkFBQSxFQUFBLFlBQUEsRUFBQSxXQUFBLEVBQUEsWUFBQSxFQUFBLE1BQUEsRUFBQSxRQUFBLEVBQUEsU0FBQSxFQUFBLEtBQUEsRUFBQSxVQUFBLEVBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBOztBQUVBLFdBQUEsV0FBQSxHQUFBLFFBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsU0FBQTs7QUFFQSxXQUFBLEtBQUEsR0FBQSxLQUFBOztBQUVBLFdBQUEsVUFBQSxHQUFBLFVBQUE7O0FBRUEsV0FBQSxXQUFBLEdBQUEsWUFBQTs7QUFFQSxlQUFBLE9BQUEsR0FBQSxLQUFBLEdBQUE7O0FBRUEsS0FKQTs7O0FBUUEsYUFBQSxhQUFBLEdBQUE7QUFDQSxlQUFBLE9BQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxRQUFBLE9BQUEsV0FBQSxDQUFBLENBQUEsRUFBQSxDQUFBLENBQUE7O0FBR0EsYUFBQSxJQUFBLElBQUEsSUFBQSxLQUFBLEVBQUE7QUFDQSxnQkFBQSxTQUFBLFlBQUEsSUFBQSxTQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsSUFBQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTs7O0FBR0EsYUFBQSxVQUFBLEdBQUE7QUFDQSxlQUFBLGFBQUEsR0FBQSxFQUFBO0FBQ0EsZUFBQSxXQUFBLENBQUEsQ0FBQSxFQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLFlBQUEsRUFBQTtBQUNBLGlCQUFBLElBQUEsSUFBQSxJQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBLFVBQUEsSUFBQSxDQUFBLElBQUEsSUFBQSxDQUFBO0FBQ0E7QUFDQSxtQkFBQSxhQUFBLENBQUEsSUFBQSxDQUFBLFNBQUE7QUFDQSxTQU5BO0FBT0E7OztBQUdBOztBQUdBLFdBQUEsYUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLE9BQUEsRUFBQSxLQUFBLEVBQUEsTUFBQSxFQUFBO0FBQ0EsMEJBQUEsS0FBQTtBQUNBLGdCQUFBLEdBQUEsQ0FBQSxNQUFBLEVBQUEsT0FBQSxVQUFBO0FBQ0EsZ0JBQUEsR0FBQSxDQUFBLE1BQUEsRUFBQSxPQUFBLEVBQUEsS0FBQSxFQUFBLE1BQUEsRUFBQSxhQUFBLFNBQUE7QUFDQSxxQkFBQSxlQUFBLENBQUEsTUFBQSxF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aW5kb3cuYXBwID0gYW5ndWxhci5tb2R1bGUoJ0Z1bGxzdGFja0dlbmVyYXRlZEFwcCcsIFsnZnNhUHJlQnVpbHQnLCAndWkucm91dGVyJywgJ3VpLmJvb3RzdHJhcCcsICduZ0FuaW1hdGUnXSk7XG5cbmFwcC5jb25maWcoZnVuY3Rpb24gKCR1cmxSb3V0ZXJQcm92aWRlciwgJGxvY2F0aW9uUHJvdmlkZXIpIHtcbiAgICAvLyBUaGlzIHR1cm5zIG9mZiBoYXNoYmFuZyB1cmxzICgvI2Fib3V0KSBhbmQgY2hhbmdlcyBpdCB0byBzb21ldGhpbmcgbm9ybWFsICgvYWJvdXQpXG4gICAgJGxvY2F0aW9uUHJvdmlkZXIuaHRtbDVNb2RlKHRydWUpO1xuICAgIC8vIElmIHdlIGdvIHRvIGEgVVJMIHRoYXQgdWktcm91dGVyIGRvZXNuJ3QgaGF2ZSByZWdpc3RlcmVkLCBnbyB0byB0aGUgXCIvXCIgdXJsLlxuICAgICR1cmxSb3V0ZXJQcm92aWRlci5vdGhlcndpc2UoJy8nKTtcbiAgICAvLyBUcmlnZ2VyIHBhZ2UgcmVmcmVzaCB3aGVuIGFjY2Vzc2luZyBhbiBPQXV0aCByb3V0ZVxuICAgICR1cmxSb3V0ZXJQcm92aWRlci53aGVuKCcvYXV0aC86cHJvdmlkZXInLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKTtcbiAgICB9KTtcbn0pO1xuXG4vLyBUaGlzIGFwcC5ydW4gaXMgZm9yIGNvbnRyb2xsaW5nIGFjY2VzcyB0byBzcGVjaWZpYyBzdGF0ZXMuXG5hcHAucnVuKGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBdXRoU2VydmljZSwgJHN0YXRlKSB7XG5cbiAgICAvLyBUaGUgZ2l2ZW4gc3RhdGUgcmVxdWlyZXMgYW4gYXV0aGVudGljYXRlZCB1c2VyLlxuICAgIHZhciBkZXN0aW5hdGlvblN0YXRlUmVxdWlyZXNBdXRoID0gZnVuY3Rpb24gKHN0YXRlKSB7XG4gICAgICAgIHJldHVybiBzdGF0ZS5kYXRhICYmIHN0YXRlLmRhdGEuYXV0aGVudGljYXRlO1xuICAgIH07XG5cbiAgICAvLyAkc3RhdGVDaGFuZ2VTdGFydCBpcyBhbiBldmVudCBmaXJlZFxuICAgIC8vIHdoZW5ldmVyIHRoZSBwcm9jZXNzIG9mIGNoYW5naW5nIGEgc3RhdGUgYmVnaW5zLlxuICAgICRyb290U2NvcGUuJG9uKCckc3RhdGVDaGFuZ2VTdGFydCcsIGZ1bmN0aW9uIChldmVudCwgdG9TdGF0ZSwgdG9QYXJhbXMpIHtcblxuICAgICAgICBpZiAoIWRlc3RpbmF0aW9uU3RhdGVSZXF1aXJlc0F1dGgodG9TdGF0ZSkpIHtcbiAgICAgICAgICAgIC8vIFRoZSBkZXN0aW5hdGlvbiBzdGF0ZSBkb2VzIG5vdCByZXF1aXJlIGF1dGhlbnRpY2F0aW9uXG4gICAgICAgICAgICAvLyBTaG9ydCBjaXJjdWl0IHdpdGggcmV0dXJuLlxuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICAgICAvLyBUaGUgdXNlciBpcyBhdXRoZW50aWNhdGVkLlxuICAgICAgICAgICAgLy8gU2hvcnQgY2lyY3VpdCB3aXRoIHJldHVybi5cbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIENhbmNlbCBuYXZpZ2F0aW5nIHRvIG5ldyBzdGF0ZS5cbiAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcblxuICAgICAgICBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKS50aGVuKGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgICAvLyBJZiBhIHVzZXIgaXMgcmV0cmlldmVkLCB0aGVuIHJlbmF2aWdhdGUgdG8gdGhlIGRlc3RpbmF0aW9uXG4gICAgICAgICAgICAvLyAodGhlIHNlY29uZCB0aW1lLCBBdXRoU2VydmljZS5pc0F1dGhlbnRpY2F0ZWQoKSB3aWxsIHdvcmspXG4gICAgICAgICAgICAvLyBvdGhlcndpc2UsIGlmIG5vIHVzZXIgaXMgbG9nZ2VkIGluLCBnbyB0byBcImxvZ2luXCIgc3RhdGUuXG4gICAgICAgICAgICBpZiAodXNlcikge1xuICAgICAgICAgICAgICAgICRzdGF0ZS5nbyh0b1N0YXRlLm5hbWUsIHRvUGFyYW1zKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgJHN0YXRlLmdvKCdsb2dpbicpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcblxuICAgIH0pO1xuXG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG5cbiAgICAvLyBSZWdpc3RlciBvdXIgKmFib3V0KiBzdGF0ZS5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYWJvdXQnLCB7XG4gICAgICAgIHVybDogJy9hYm91dCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdBYm91dENvbnRyb2xsZXInLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2Fib3V0L2Fib3V0Lmh0bWwnXG4gICAgfSk7XG5cbn0pO1xuXG5hcHAuY29udHJvbGxlcignQWJvdXRDb250cm9sbGVyJywgZnVuY3Rpb24gKCRzY29wZSwgRnVsbHN0YWNrUGljcykge1xuXG4gICAgLy8gSW1hZ2VzIG9mIGJlYXV0aWZ1bCBGdWxsc3RhY2sgcGVvcGxlLlxuICAgICRzY29wZS5pbWFnZXMgPSBfLnNodWZmbGUoRnVsbHN0YWNrUGljcyk7XG5cbn0pOyIsImFwcC5jb250cm9sbGVyKCdDcmVhdGVkYkN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCAkc3RhdGUsIENyZWF0ZWRiRmFjdG9yeSkge1xuXG5cdCRzY29wZS5jcmVhdGVkREIgPSBmYWxzZTtcbiAgICAgICAgJHNjb3BlLmNvbHVtbkFycmF5ID0gW107XG5cblx0JHNjb3BlLmFkZCA9IGZ1bmN0aW9uKCkge1xuXHRcdCRzY29wZS5jb2x1bW5BcnJheS5wdXNoKCcxJyk7XG5cdH1cblxuXHQkc2NvcGUuY3JlYXRlREIgPSBmdW5jdGlvbihuYW1lKSB7XG5cdFx0Q3JlYXRlZGJGYWN0b3J5LmNyZWF0ZURCKG5hbWUpXG5cdFx0LnRoZW4oZnVuY3Rpb24oZGF0YSkge1xuXHRcdFx0JHNjb3BlLmNyZWF0ZWREQiA9IGRhdGE7XG5cdFx0fSlcblx0fVxuXG5cdCRzY29wZS5jcmVhdGVUYWJsZSA9IGZ1bmN0aW9uKHRhYmxlLCBEQil7XG5cdFx0Q3JlYXRlZGJGYWN0b3J5LmNyZWF0ZVRhYmxlKHRhYmxlLCBEQilcblx0XHRcdCRzdGF0ZS5nbygnVGFibGUnLCB7ZGJOYW1lOiAkc2NvcGUuY3JlYXRlZERCLmRiTmFtZX0sIHtyZWxvYWQ6dHJ1ZX0pXG5cdH1cbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ0NyZWF0ZWRiRmFjdG9yeScsIGZ1bmN0aW9uICgkaHR0cCkge1xuXG5cdHZhciBDcmVhdGVkYkZhY3RvcnkgPSB7fTtcblxuXHRmdW5jdGlvbiByZXNUb0RhdGEocmVzKSB7XG4gICAgICAgIHJldHVybiByZXMuZGF0YTtcbiAgICB9XG5cbiAgICBDcmVhdGVkYkZhY3RvcnkuY3JlYXRlREIgPSBmdW5jdGlvbihkYk5hbWUpIHtcbiAgICBcdHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL21hc3RlcmRiJywgZGJOYW1lKVxuICAgIFx0LnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgQ3JlYXRlZGJGYWN0b3J5LmNyZWF0ZVRhYmxlID0gZnVuY3Rpb24odGFibGUsIGNyZWF0ZWREQikge1xuICAgIHRhYmxlLmRiTmFtZSA9IGNyZWF0ZWREQi5kYk5hbWU7XG4gICAgcmV0dXJuICRodHRwLnBvc3QoJy9hcGkvY2xpZW50ZGInLCB0YWJsZSlcbiAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgfVxuXG5cdHJldHVybiBDcmVhdGVkYkZhY3Rvcnk7IFxufSlcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2NyZWF0ZWRiJywge1xuICAgICAgICB1cmw6ICcvY3JlYXRlZGInLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2NyZWF0ZWRiL2NyZWF0ZWRiLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnQ3JlYXRlZGJDdHJsJyxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICBcdGxvZ2dlZEluVXNlcjogZnVuY3Rpb24oQXV0aFNlcnZpY2UpIHtcbiAgICAgICAgXHRcdHJldHVybiBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKTtcbiAgICAgICAgXHR9XG4gICAgICAgIH1cbiAgICB9KTtcblxufSk7IiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnZG9jcycsIHtcbiAgICAgICAgdXJsOiAnL2RvY3MnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2RvY3MvZG9jcy5odG1sJ1xuICAgIH0pO1xufSk7XG4iLCIoZnVuY3Rpb24gKCkge1xuXG4gICAgJ3VzZSBzdHJpY3QnO1xuXG4gICAgLy8gSG9wZSB5b3UgZGlkbid0IGZvcmdldCBBbmd1bGFyISBEdWgtZG95LlxuICAgIGlmICghd2luZG93LmFuZ3VsYXIpIHRocm93IG5ldyBFcnJvcignSSBjYW5cXCd0IGZpbmQgQW5ndWxhciEnKTtcblxuICAgIHZhciBhcHAgPSBhbmd1bGFyLm1vZHVsZSgnZnNhUHJlQnVpbHQnLCBbXSk7XG5cbiAgICBhcHAuZmFjdG9yeSgnU29ja2V0JywgZnVuY3Rpb24gKCkge1xuICAgICAgICBpZiAoIXdpbmRvdy5pbykgdGhyb3cgbmV3IEVycm9yKCdzb2NrZXQuaW8gbm90IGZvdW5kIScpO1xuICAgICAgICByZXR1cm4gd2luZG93LmlvKHdpbmRvdy5sb2NhdGlvbi5vcmlnaW4pO1xuICAgIH0pO1xuXG4gICAgLy8gQVVUSF9FVkVOVFMgaXMgdXNlZCB0aHJvdWdob3V0IG91ciBhcHAgdG9cbiAgICAvLyBicm9hZGNhc3QgYW5kIGxpc3RlbiBmcm9tIGFuZCB0byB0aGUgJHJvb3RTY29wZVxuICAgIC8vIGZvciBpbXBvcnRhbnQgZXZlbnRzIGFib3V0IGF1dGhlbnRpY2F0aW9uIGZsb3cuXG4gICAgYXBwLmNvbnN0YW50KCdBVVRIX0VWRU5UUycsIHtcbiAgICAgICAgbG9naW5TdWNjZXNzOiAnYXV0aC1sb2dpbi1zdWNjZXNzJyxcbiAgICAgICAgbG9naW5GYWlsZWQ6ICdhdXRoLWxvZ2luLWZhaWxlZCcsXG4gICAgICAgIGxvZ291dFN1Y2Nlc3M6ICdhdXRoLWxvZ291dC1zdWNjZXNzJyxcbiAgICAgICAgc2Vzc2lvblRpbWVvdXQ6ICdhdXRoLXNlc3Npb24tdGltZW91dCcsXG4gICAgICAgIG5vdEF1dGhlbnRpY2F0ZWQ6ICdhdXRoLW5vdC1hdXRoZW50aWNhdGVkJyxcbiAgICAgICAgbm90QXV0aG9yaXplZDogJ2F1dGgtbm90LWF1dGhvcml6ZWQnXG4gICAgfSk7XG5cbiAgICBhcHAuZmFjdG9yeSgnQXV0aEludGVyY2VwdG9yJywgZnVuY3Rpb24gKCRyb290U2NvcGUsICRxLCBBVVRIX0VWRU5UUykge1xuICAgICAgICB2YXIgc3RhdHVzRGljdCA9IHtcbiAgICAgICAgICAgIDQwMTogQVVUSF9FVkVOVFMubm90QXV0aGVudGljYXRlZCxcbiAgICAgICAgICAgIDQwMzogQVVUSF9FVkVOVFMubm90QXV0aG9yaXplZCxcbiAgICAgICAgICAgIDQxOTogQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsXG4gICAgICAgICAgICA0NDA6IEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0XG4gICAgICAgIH07XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3Qoc3RhdHVzRGljdFtyZXNwb25zZS5zdGF0dXNdLCByZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZXNwb25zZSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICB9KTtcblxuICAgIGFwcC5jb25maWcoZnVuY3Rpb24gKCRodHRwUHJvdmlkZXIpIHtcbiAgICAgICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaChbXG4gICAgICAgICAgICAnJGluamVjdG9yJyxcbiAgICAgICAgICAgIGZ1bmN0aW9uICgkaW5qZWN0b3IpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gJGluamVjdG9yLmdldCgnQXV0aEludGVyY2VwdG9yJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIF0pO1xuICAgIH0pO1xuXG4gICAgYXBwLnNlcnZpY2UoJ0F1dGhTZXJ2aWNlJywgZnVuY3Rpb24gKCRodHRwLCBTZXNzaW9uLCAkcm9vdFNjb3BlLCBBVVRIX0VWRU5UUywgJHEpIHtcblxuICAgICAgICBmdW5jdGlvbiBvblN1Y2Nlc3NmdWxMb2dpbihyZXNwb25zZSkge1xuICAgICAgICAgICAgdmFyIGRhdGEgPSByZXNwb25zZS5kYXRhO1xuICAgICAgICAgICAgU2Vzc2lvbi5jcmVhdGUoZGF0YS5pZCwgZGF0YS51c2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChBVVRIX0VWRU5UUy5sb2dpblN1Y2Nlc3MpO1xuICAgICAgICAgICAgcmV0dXJuIGRhdGEudXNlcjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIFVzZXMgdGhlIHNlc3Npb24gZmFjdG9yeSB0byBzZWUgaWYgYW5cbiAgICAgICAgLy8gYXV0aGVudGljYXRlZCB1c2VyIGlzIGN1cnJlbnRseSByZWdpc3RlcmVkLlxuICAgICAgICB0aGlzLmlzQXV0aGVudGljYXRlZCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiAhIVNlc3Npb24udXNlcjtcbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLmdldExvZ2dlZEluVXNlciA9IGZ1bmN0aW9uIChmcm9tU2VydmVyKSB7XG5cbiAgICAgICAgICAgIC8vIElmIGFuIGF1dGhlbnRpY2F0ZWQgc2Vzc2lvbiBleGlzdHMsIHdlXG4gICAgICAgICAgICAvLyByZXR1cm4gdGhlIHVzZXIgYXR0YWNoZWQgdG8gdGhhdCBzZXNzaW9uXG4gICAgICAgICAgICAvLyB3aXRoIGEgcHJvbWlzZS4gVGhpcyBlbnN1cmVzIHRoYXQgd2UgY2FuXG4gICAgICAgICAgICAvLyBhbHdheXMgaW50ZXJmYWNlIHdpdGggdGhpcyBtZXRob2QgYXN5bmNocm9ub3VzbHkuXG5cbiAgICAgICAgICAgIC8vIE9wdGlvbmFsbHksIGlmIHRydWUgaXMgZ2l2ZW4gYXMgdGhlIGZyb21TZXJ2ZXIgcGFyYW1ldGVyLFxuICAgICAgICAgICAgLy8gdGhlbiB0aGlzIGNhY2hlZCB2YWx1ZSB3aWxsIG5vdCBiZSB1c2VkLlxuXG4gICAgICAgICAgICBpZiAodGhpcy5pc0F1dGhlbnRpY2F0ZWQoKSAmJiBmcm9tU2VydmVyICE9PSB0cnVlKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRxLndoZW4oU2Vzc2lvbi51c2VyKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gTWFrZSByZXF1ZXN0IEdFVCAvc2Vzc2lvbi5cbiAgICAgICAgICAgIC8vIElmIGl0IHJldHVybnMgYSB1c2VyLCBjYWxsIG9uU3VjY2Vzc2Z1bExvZ2luIHdpdGggdGhlIHJlc3BvbnNlLlxuICAgICAgICAgICAgLy8gSWYgaXQgcmV0dXJucyBhIDQwMSByZXNwb25zZSwgd2UgY2F0Y2ggaXQgYW5kIGluc3RlYWQgcmVzb2x2ZSB0byBudWxsLlxuICAgICAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL3Nlc3Npb24nKS50aGVuKG9uU3VjY2Vzc2Z1bExvZ2luKS5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICB9KTtcblxuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMuc2lnbnVwID0gZnVuY3Rpb24oY3JlZGVudGlhbHMpe1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9zaWdudXAnLCBjcmVkZW50aWFscylcbiAgICAgICAgICAgIC50aGVuKG9uU3VjY2Vzc2Z1bExvZ2luKVxuICAgICAgICAgICAgLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHsgbWVzc2FnZTogJ0ludmFsaWQgc2lnbnVwIGNyZWRlbnRpYWxzLicgfSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLmxvZ2luID0gZnVuY3Rpb24gKGNyZWRlbnRpYWxzKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL2xvZ2luJywgY3JlZGVudGlhbHMpXG4gICAgICAgICAgICAgICAgLnRoZW4ob25TdWNjZXNzZnVsTG9naW4pXG4gICAgICAgICAgICAgICAgLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdCh7IG1lc3NhZ2U6ICdJbnZhbGlkIGxvZ2luIGNyZWRlbnRpYWxzLicgfSk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5sb2dvdXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvbG9nb3V0JykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgU2Vzc2lvbi5kZXN0cm95KCk7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KEFVVEhfRVZFTlRTLmxvZ291dFN1Y2Nlc3MpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICB9KTtcblxuICAgIGFwcC5zZXJ2aWNlKCdTZXNzaW9uJywgZnVuY3Rpb24gKCRyb290U2NvcGUsIEFVVEhfRVZFTlRTKSB7XG5cbiAgICAgICAgdmFyIHNlbGYgPSB0aGlzO1xuXG4gICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLm5vdEF1dGhlbnRpY2F0ZWQsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHNlbGYuZGVzdHJveSgpO1xuICAgICAgICB9KTtcblxuICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5zZXNzaW9uVGltZW91dCwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgc2VsZi5kZXN0cm95KCk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIHRoaXMuaWQgPSBudWxsO1xuICAgICAgICB0aGlzLnVzZXIgPSBudWxsO1xuXG4gICAgICAgIHRoaXMuY3JlYXRlID0gZnVuY3Rpb24gKHNlc3Npb25JZCwgdXNlcikge1xuICAgICAgICAgICAgdGhpcy5pZCA9IHNlc3Npb25JZDtcbiAgICAgICAgICAgIHRoaXMudXNlciA9IHVzZXI7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5kZXN0cm95ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgdGhpcy5pZCA9IG51bGw7XG4gICAgICAgICAgICB0aGlzLnVzZXIgPSBudWxsO1xuICAgICAgICB9O1xuXG4gICAgfSk7XG5cbn0pKCk7XG4iLCJhcHAuY29udHJvbGxlcignSG9tZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBhbGxEYnMsICRzdGF0ZSkge1xuXG5cdCRzY29wZS5hbGxEYnMgPSBhbGxEYnM7XG59KTtcbiIsImFwcC5mYWN0b3J5KCdIb21lRmFjdG9yeScsIGZ1bmN0aW9uICgkaHR0cCkge1xuXG5cdHZhciBIb21lRmFjdG9yeSA9IHt9O1xuXG5cdGZ1bmN0aW9uIHJlc1RvRGF0YShyZXMpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5kYXRhO1xuICAgIH1cblxuICAgIEhvbWVGYWN0b3J5LmdldEFsbERicyA9IGZ1bmN0aW9uKCl7XG4gICAgXHRyZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL21hc3RlcmRiJylcbiAgICBcdC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgICBIb21lRmFjdG9yeS5kZWxldGVEQiA9IGZ1bmN0aW9uKG5hbWUpe1xuICAgIFx0cmV0dXJuICRodHRwLmRlbGV0ZSgnL2FwaS9tYXN0ZXJkYi8nICsgbmFtZSlcbiAgICBcdC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cblx0cmV0dXJuIEhvbWVGYWN0b3J5OyBcbn0pIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnSG9tZScsIHtcbiAgICAgICAgdXJsOiAnL2hvbWUnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL0hvbWUvSG9tZS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0hvbWVDdHJsJyxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICBcdGFsbERiczogZnVuY3Rpb24oSG9tZUZhY3Rvcnkpe1xuICAgICAgICBcdFx0cmV0dXJuIEhvbWVGYWN0b3J5LmdldEFsbERicygpO1xuICAgICAgICBcdH0sXG4gICAgICAgICAgICBsb2dnZWRJblVzZXI6IGZ1bmN0aW9uIChBdXRoU2VydmljZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pO1xufSk7IiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnbGFuZGluZ1BhZ2UnLCB7XG4gICAgICAgIHVybDogJy8nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2xhbmRpbmdQYWdlL2xhbmRpbmdQYWdlLmh0bWwnXG4gICAgICAgIH1cbiAgICApO1xuXG59KTsiLCJhcHAuY29uZmlnKGZ1bmN0aW9uKCRzdGF0ZVByb3ZpZGVyKSB7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnbG9naW4nLCB7XG4gICAgICAgIHVybDogJy9sb2dpbicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvbG9naW4vbG9naW4uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdMb2dpbkN0cmwnXG4gICAgfSk7XG5cbn0pO1xuXG5hcHAuY29udHJvbGxlcignTG9naW5DdHJsJywgZnVuY3Rpb24oJHNjb3BlLCBBdXRoU2VydmljZSwgJHN0YXRlKSB7XG5cbiAgICAkc2NvcGUubG9naW4gPSB7fTtcbiAgICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICAgJHNjb3BlLnNlbmRMb2dpbiA9IGZ1bmN0aW9uKGxvZ2luSW5mbykge1xuXG4gICAgICAgICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgICAgICAgQXV0aFNlcnZpY2UubG9naW4obG9naW5JbmZvKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKCdIb21lJyk7XG4gICAgICAgIH0pLmNhdGNoKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgJHNjb3BlLmVycm9yID0gJ0ludmFsaWQgbG9naW4gY3JlZGVudGlhbHMuJztcbiAgICAgICAgfSk7XG5cbiAgICB9O1xuXG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnbWVtYmVyc09ubHknLCB7XG4gICAgICAgIHVybDogJy9tZW1iZXJzLWFyZWEnLFxuICAgICAgICB0ZW1wbGF0ZTogJzxpbWcgbmctcmVwZWF0PVwiaXRlbSBpbiBzdGFzaFwiIHdpZHRoPVwiMzAwXCIgbmctc3JjPVwie3sgaXRlbSB9fVwiIC8+JyxcbiAgICAgICAgY29udHJvbGxlcjogZnVuY3Rpb24gKCRzY29wZSwgU2VjcmV0U3Rhc2gpIHtcbiAgICAgICAgICAgIFNlY3JldFN0YXNoLmdldFN0YXNoKCkudGhlbihmdW5jdGlvbiAoc3Rhc2gpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuc3Rhc2ggPSBzdGFzaDtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9LFxuICAgICAgICAvLyBUaGUgZm9sbG93aW5nIGRhdGEuYXV0aGVudGljYXRlIGlzIHJlYWQgYnkgYW4gZXZlbnQgbGlzdGVuZXJcbiAgICAgICAgLy8gdGhhdCBjb250cm9scyBhY2Nlc3MgdG8gdGhpcyBzdGF0ZS4gUmVmZXIgdG8gYXBwLmpzLlxuICAgICAgICBkYXRhOiB7XG4gICAgICAgICAgICBhdXRoZW50aWNhdGU6IHRydWVcbiAgICAgICAgfVxuICAgIH0pO1xuXG59KTtcblxuYXBwLmZhY3RvcnkoJ1NlY3JldFN0YXNoJywgZnVuY3Rpb24gKCRodHRwKSB7XG5cbiAgICB2YXIgZ2V0U3Rhc2ggPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvbWVtYmVycy9zZWNyZXQtc3Rhc2gnKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmRhdGE7XG4gICAgICAgIH0pO1xuICAgIH07XG5cbiAgICByZXR1cm4ge1xuICAgICAgICBnZXRTdGFzaDogZ2V0U3Rhc2hcbiAgICB9O1xuXG59KTsiLCIndXNlIHN0cmljdCc7XG5cbmFwcC5kaXJlY3RpdmUoJ29hdXRoQnV0dG9uJywgZnVuY3Rpb24gKCkge1xuICByZXR1cm4ge1xuICAgIHNjb3BlOiB7XG4gICAgICBwcm92aWRlck5hbWU6ICdAJ1xuICAgIH0sXG4gICAgcmVzdHJpY3Q6ICdFJyxcbiAgICB0ZW1wbGF0ZVVybDogJy9qcy9vYXV0aC9vYXV0aC1idXR0b24uaHRtbCdcbiAgfVxufSk7XG4iLCJhcHAuY29udHJvbGxlcignQXNzb2NpYXRpb25JbnN0YW5jZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCAkdWliTW9kYWxJbnN0YW5jZSwgZm9yZWlnbkNvbHMsIFRhYmxlRmFjdG9yeSwgSG9tZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgJHN0YXRlLCBmb3JUYWJsZSwgZm9yVGFibGVOYW1lLCBjdXJyVGFibGUsIGNvbE5hbWUsIGlkMSkge1xuXG4gICRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lO1xuXG4gICRzY29wZS5zaW5nbGVUYWJsZSA9IGZvclRhYmxlO1xuXG4gICRzY29wZS5UYWJsZU5hbWUgPSBmb3JUYWJsZU5hbWU7XG5cbiAgJHNjb3BlLmN1cnJUYWJsZSA9IGN1cnJUYWJsZTtcblxuICAkc2NvcGUuY29sTmFtZSA9IGNvbE5hbWU7XG5cbiAgJHNjb3BlLmlkMSA9IGlkMTtcblxuICAkc2NvcGUuc2V0U2VsZWN0ZWQgPSBmdW5jdGlvbigpe1xuXG4gICAgJHNjb3BlLmN1cnJSb3cgPSB0aGlzLnJvdztcbiAgICBjb25zb2xlLmxvZygkc2NvcGUuY3VyclJvdyk7XG4gIH1cblxuIFxuXG4gIGZ1bmN0aW9uIENyZWF0ZUNvbHVtbnMoKXtcbiAgICAkc2NvcGUuY29sdW1ucyA9IFtdO1xuICAgIHZhciB0YWJsZSA9IGZvclRhYmxlWzBdO1xuXG5cbiAgICBmb3IodmFyIHByb3AgaW4gdGFibGUpe1xuICAgICAgaWYocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jyl7XG4gICAgICAgICRzY29wZS5jb2x1bW5zLnB1c2gocHJvcCk7ICBcbiAgICAgIH0gXG4gICAgfVxuICB9XG5cbiAgICBDcmVhdGVDb2x1bW5zKCk7XG5cblxuICAgIC8vdGhpcyBmdW5jdGlvbiB3aWxsIHJlIHJ1biB3aGVuIHRoZSBmaWx0ZXIgZnVuY3Rpb24gaXMgaW52b2tlZCwgaW4gb3JkZXIgdG8gcmVwb3B1bGF0ZSB0aGUgdGFibGVcbiAgICBmdW5jdGlvbiBDcmVhdGVSb3dzKCkge1xuICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheSA9IFtdO1xuICAgICAgICBmb3JUYWJsZS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgdmFyIHJvd1ZhbHVlcyA9IFtdO1xuICAgICAgICAgICAgZm9yICh2YXIgcHJvcCBpbiByb3cpIHtcbiAgICAgICAgICAgICAgICBpZiAocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jykgcm93VmFsdWVzLnB1c2gocm93W3Byb3BdKVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkucHVzaChyb3dWYWx1ZXMpXG4gICAgICAgIH0pXG4gICAgfVxuXG4gICAgLy8gU29ydCB0aGUgdmFsdWVzIGluIHNpbmdsZVRhYmxlIHNvIHRoYXQgYWxsIHRoZSB2YWx1ZXMgZm9yIGEgZ2l2ZW4gcm93IGFyZSBncm91cGVkXG4gICAgQ3JlYXRlUm93cygpO1xuXG5cbiAgJHNjb3BlLnNldEZvcmVpZ25LZXkgPSBmdW5jdGlvbihkYk5hbWUsIHRibE5hbWUsIGNvbE5hbWUsIGlkMSwgaWQyKXtcbiAgICAkdWliTW9kYWxJbnN0YW5jZS5jbG9zZSgpO1xuICAgIFRhYmxlRmFjdG9yeS5zZXRGb3JlaWduS2V5KGRiTmFtZSwgdGJsTmFtZSwgY29sTmFtZSwgaWQxLCBpZDIpXG4gICAgLnRoZW4oZnVuY3Rpb24oKXtcbiAgICAgICAgJHN0YXRlLmdvKCdUYWJsZS5TaW5nbGUnLCB7IGRiTmFtZTogJHNjb3BlLmRiTmFtZSwgdGFibGVOYW1lOiAkc2NvcGUuY3VyclRhYmxlIH0sIHsgcmVsb2FkOiB0cnVlIH0pXG4gICAgfSlcbiAgfVxuXG5cblxuICAkc2NvcGUub2sgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoJHNjb3BlLnNlbGVjdGVkLml0ZW0pO1xuICB9O1xuXG4gICRzY29wZS5jYW5jZWwgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuZGlzbWlzcygnY2FuY2VsJyk7XG4gIH07XG59KTsiLCJhcHAuY29udHJvbGxlcignZGVsZXRlREJDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHVpYk1vZGFsLCAkbG9nKSB7XG5cbiAgJHNjb3BlLml0ZW1zID0gWydpdGVtMScsICdpdGVtMicsICdpdGVtMyddO1xuXG4gICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9IHRydWU7XG5cbiAgJHNjb3BlLm9wZW4gPSBmdW5jdGlvbiAoc2l6ZSkge1xuXG4gICAgdmFyIG1vZGFsSW5zdGFuY2UgPSAkdWliTW9kYWwub3Blbih7XG4gICAgICBhbmltYXRpb246ICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCxcbiAgICAgIHRlbXBsYXRlVXJsOiAnZGVsZXRlREJDb250ZW50Lmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ2RlbGV0ZURCSW5zdGFuY2VDdHJsJyxcbiAgICAgIHNpemU6IHNpemUsXG4gICAgICByZXNvbHZlOiB7XG4gICAgICAgIGl0ZW1zOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgcmV0dXJuICRzY29wZS5pdGVtcztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbiAoc2VsZWN0ZWRJdGVtKSB7XG4gICAgICAkc2NvcGUuc2VsZWN0ZWQgPSBzZWxlY3RlZEl0ZW07XG4gICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgJGxvZy5pbmZvKCdNb2RhbCBkaXNtaXNzZWQgYXQ6ICcgKyBuZXcgRGF0ZSgpKTtcbiAgICB9KTtcbiAgfTtcblxuICAkc2NvcGUudG9nZ2xlQW5pbWF0aW9uID0gZnVuY3Rpb24gKCkge1xuICAgICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9ICEkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQ7XG4gIH07XG5cbn0pO1xuXG5hcHAuY29udHJvbGxlcignZGVsZXRlREJJbnN0YW5jZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCAkdWliTW9kYWxJbnN0YW5jZSwgaXRlbXMsIFRhYmxlRmFjdG9yeSwgSG9tZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgJHN0YXRlKSB7XG5cblxuICAkc2NvcGUuZHJvcERiVGV4dCA9ICdEUk9QIERBVEFCQVNFJ1xuICAkc2NvcGUuZGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZTtcblxuICAkc2NvcGUuZGVsZXRlVGhlRGIgPSBmdW5jdGlvbigpe1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmNsb3NlKCRzY29wZS5zZWxlY3RlZC5pdGVtKTtcbiAgICBUYWJsZUZhY3RvcnkuZGVsZXRlRGIoJHNjb3BlLmRiTmFtZSlcbiAgICAudGhlbihmdW5jdGlvbigpe1xuICAgICAgSG9tZUZhY3RvcnkuZGVsZXRlREIoJHNjb3BlLmRiTmFtZSlcbiAgICB9KVxuICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgJHN0YXRlLmdvKCdIb21lJywge30sIHtyZWxvYWQgOiB0cnVlfSlcbiAgICB9KVxuICB9XG5cbiAgJHNjb3BlLml0ZW1zID0gaXRlbXM7XG4gICRzY29wZS5zZWxlY3RlZCA9IHtcbiAgICBpdGVtOiAkc2NvcGUuaXRlbXNbMF1cbiAgfTtcblxuICAkc2NvcGUub2sgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoJHNjb3BlLnNlbGVjdGVkLml0ZW0pO1xuICB9O1xuXG4gICRzY29wZS5jYW5jZWwgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuZGlzbWlzcygnY2FuY2VsJyk7XG4gIH07XG59KTsiLCJhcHAuY29udHJvbGxlcignRGVsZXRlRGJDdHJsJywgZnVuY3Rpb24gKCRzY29wZSkge1xuXG4gICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9IHRydWU7XG5cbiAgJHNjb3BlLm9wZW4gPSBmdW5jdGlvbiAoc2l6ZSkge1xuXG4gICAgdmFyIG1vZGFsSW5zdGFuY2UgPSAkdWliTW9kYWwub3Blbih7XG4gICAgICBhbmltYXRpb246ICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCxcbiAgICAgIHRlbXBsYXRlVXJsOiAnZGVsZXRlRGJDb250ZW50Lmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0RlbGV0ZURiSW5zdGFuY2VDdHJsJyxcbiAgICAgIHNpemU6IHNpemUsXG4gICAgICByZXNvbHZlOiB7XG4gICAgICAgIGl0ZW1zOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgcmV0dXJuICRzY29wZS5pdGVtcztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbiAoc2VsZWN0ZWRJdGVtKSB7XG4gICAgICAkc2NvcGUuc2VsZWN0ZWQgPSBzZWxlY3RlZEl0ZW07XG4gICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgJGxvZy5pbmZvKCdNb2RhbCBkaXNtaXNzZWQgYXQ6ICcgKyBuZXcgRGF0ZSgpKTtcbiAgICB9KTtcbiAgfTtcblxufSk7XG5cblxuYXBwLmNvbnRyb2xsZXIoJ0RlbGV0ZURiSW5zdGFuY2VDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHVpYk1vZGFsSW5zdGFuY2UsIGl0ZW1zLCAkc3RhdGVQYXJhbXMsIFRhYmxlRmFjdG9yeSkge1xuXG4gICRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lXG5cbiAgJHNjb3BlLmRyb3BEYXRhYmFzZSA9ICdEUk9QIERBVEFCQVNFJ1xuXG4gICRzY29wZS5kZWxldGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgVGFibGVGYWN0b3J5LmRlbGV0ZURiKCRzY29wZS5kYk5hbWUpXG4gICAgJHN0YXRlLmdvKCdIb21lJywge30sIHtyZWxvYWQgOiB0cnVlfSlcbiAgfTtcblxuICAkc2NvcGUuY2FuY2VsID0gZnVuY3Rpb24gKCkge1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmRpc21pc3MoJ2NhbmNlbCcpO1xuICB9O1xufSk7IiwiYXBwLmNvbnRyb2xsZXIoJ0pvaW5UYWJsZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgam9pblRhYmxlKSB7XG5cbiAgICAkc2NvcGUuam9pblRhYmxlID0gam9pblRhYmxlO1xuXG5cblx0ZnVuY3Rpb24gQ3JlYXRlQ29sdW1ucygpe1xuXHRcdCRzY29wZS5jb2x1bW5zID0gW107XG5cdFx0dmFyIHRhYmxlID0gJHNjb3BlLmpvaW5UYWJsZVswXTtcblxuXG5cdFx0Zm9yKHZhciBwcm9wIGluIHRhYmxlKXtcblx0XHRcdGlmKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpe1xuXHRcdFx0XHQkc2NvcGUuY29sdW1ucy5wdXNoKHByb3ApO1x0XG5cdFx0XHR9IFxuXHRcdH1cblx0fVxuXG4gICAgQ3JlYXRlQ29sdW1ucygpO1xuXG5cbiAgICAvL3RoaXMgZnVuY3Rpb24gd2lsbCByZSBydW4gd2hlbiB0aGUgZmlsdGVyIGZ1bmN0aW9uIGlzIGludm9rZWQsIGluIG9yZGVyIHRvIHJlcG9wdWxhdGUgdGhlIHRhYmxlXG4gICAgZnVuY3Rpb24gQ3JlYXRlUm93cygpIHtcbiAgICBcdHZhciBhbGlhcztcbiAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkgPSBbXTtcbiAgICAgICAgam9pblRhYmxlLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICB2YXIgcm93VmFsdWVzID0gW107XG4gICAgICAgICAgICBmb3IgKHZhciBwcm9wIGluIHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKSByb3dWYWx1ZXMucHVzaChyb3dbcHJvcF0pXG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheS5wdXNoKHJvd1ZhbHVlcylcbiAgICAgICAgfSlcbiAgICB9XG5cbiAgICAvLyBTb3J0IHRoZSB2YWx1ZXMgaW4gc2luZ2xlVGFibGUgc28gdGhhdCBhbGwgdGhlIHZhbHVlcyBmb3IgYSBnaXZlbiByb3cgYXJlIGdyb3VwZWRcbiAgICBDcmVhdGVSb3dzKCk7XG5cblxufSkiLCJhcHAuY29udHJvbGxlcignUXVlcnlUYWJsZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuXG4gICAgJHNjb3BlLnFGaWx0ZXIgPSBmdW5jdGlvbihyZWZlcmVuY2VTdHJpbmcsIHZhbCl7XG4gICAgICAgIGlmKCFyZWZlcmVuY2VTdHJpbmcpIHJldHVybiB0cnVlO1xuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIGZvcih2YXIgcHJvcCBpbiB2YWwpe1xuICAgICAgICAgICAgICAgIHZhciBjZWxsVmFsID0gdmFsW3Byb3BdLnRvU3RyaW5nKCkudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgICAgICB2YXIgc2VhcmNoVmFsID0gcmVmZXJlbmNlU3RyaW5nLnRvU3RyaW5nKCkudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhjZWxsVmFsLCBzZWFyY2hWYWwsIGNlbGxWYWwuaW5kZXhPZihzZWFyY2hWYWwpICE9PSAtMSlcbiAgICAgICAgICAgICAgICBpZihjZWxsVmFsLmluZGV4T2Yoc2VhcmNoVmFsKSAhPT0gLTEpIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbn0pIiwiYXBwLmNvbnRyb2xsZXIoJ1NpbmdsZVRhYmxlQ3RybCcsIGZ1bmN0aW9uKCRzY29wZSwgVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMsIHNpbmdsZVRhYmxlLCAkd2luZG93LCAkc3RhdGUsICR1aWJNb2RhbCwgYXNzb2NpYXRpb25zLCAkbG9nKSB7XG5cbiAgICAvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vUHV0dGluZyBzdHVmZiBvbiBzY29wZS8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgICRzY29wZS50aGVEYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lO1xuICAgICRzY29wZS50aGVUYWJsZU5hbWUgPSAkc3RhdGVQYXJhbXMudGFibGVOYW1lO1xuICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHNpbmdsZVRhYmxlWzBdLnNvcnQoZnVuY3Rpb24oYSwgYil7XG4gICAgICAgIGlmKGEuaWQgPiBiLmlkKSByZXR1cm4gMTtcbiAgICAgICAgaWYoYS5pZCA8IGIuaWQpIHJldHVybiAtMTtcbiAgICAgICAgcmV0dXJuIDA7XG4gICAgfSk7XG4gICAgJHNjb3BlLnNlbGVjdGVkQWxsID0gZmFsc2U7XG4gICAgJHNjb3BlLmFzc29jaWF0aW9ucyA9IGFzc29jaWF0aW9ucztcblxuXG4gICAgaWYoJHNjb3BlLmFzc29jaWF0aW9ucy5sZW5ndGg+MCkge1xuICAgICAgICBpZigkc2NvcGUuYXNzb2NpYXRpb25zWzBdWydUaHJvdWdoJ10gPT09ICRzdGF0ZVBhcmFtcy50YWJsZU5hbWUpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbygnVGFibGUuVGhyb3VnaCcsIHtkYk5hbWUgOiAkc3RhdGVQYXJhbXMuZGJOYW1lLCB0YWJsZU5hbWUgOiAkc3RhdGVQYXJhbXMudGFibGVOYW1lfSlcbiAgICAgICAgfVxuICAgIH1cblxuXG4gICAgZnVuY3Rpb24gZm9yZWlnbkNvbHVtbk9iaigpIHtcbiAgICAgICAgdmFyIGZvcmVpZ25Db2xzID0ge307XG4gICAgICAgICRzY29wZS5hc3NvY2lhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIGlmIChyb3cuVGFibGUxID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmIHJvdy5SZWxhdGlvbnNoaXAxID09PSAnaGFzT25lJykge1xuICAgICAgICAgICAgICAgIGZvcmVpZ25Db2xzW3Jvdy5BbGlhczFdID0gcm93LlRhYmxlMlxuICAgICAgICAgICAgfSBlbHNlIGlmIChyb3cuVGFibGUyID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmIHJvdy5SZWxhdGlvbnNoaXAyID09PSAnaGFzT25lJykge1xuICAgICAgICAgICAgICAgIGZvcmVpZ25Db2xzW3Jvdy5BbGlhczJdID0gcm93LlRhYmxlMVxuICAgICAgICAgICAgfVxuICAgICAgICB9KVxuICAgICAgICAkc2NvcGUuZm9yZWlnbkNvbHMgPSBmb3JlaWduQ29scztcbiAgICB9XG5cbiAgICBmb3JlaWduQ29sdW1uT2JqKCk7XG5cblxuICAgICRzY29wZS5jdXJyZW50VGFibGUgPSAkc3RhdGVQYXJhbXM7XG5cbiAgICAkc2NvcGUubXlJbmRleCA9IDE7XG5cbiAgICAkc2NvcGUuaWRzID0gJHNjb3BlLnNpbmdsZVRhYmxlLm1hcChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgcmV0dXJuIHJvdy5pZDtcbiAgICB9KVxuXG4gICAgLy9kZWxldGUgYSByb3cgXG4gICAgJHNjb3BlLnNob3dEZWxldGUgPSBmYWxzZTtcbiAgICAkc2NvcGUudG9nZ2xlRGVsZXRlID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICRzY29wZS5zaG93RGVsZXRlID0gISRzY29wZS5zaG93RGVsZXRlXG4gICAgfVxuXG4gICAgJHNjb3BlLmRlbGV0ZVNlbGVjdGVkID0gZnVuY3Rpb24oZGIsIHRhYmxlLCBpbnN0YW5jZUFycmF5KSB7XG4gICAgICAgIGZvcih2YXIgaSA9IGluc3RhbmNlQXJyYXkubGVuZ3RoLTE7IGkgPj0gMDsgaS0tKXtcbiAgICAgICAgICAgIHZhciByb3cgPSBpbnN0YW5jZUFycmF5W2ldO1xuICAgICAgICAgICAgdmFyIGxlbmd0aCA9IGk7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhyb3cpICAgICAgIFxuICAgICAgICAgICAgaWYgKHJvdy5zZWxlY3RlZCkge1xuICAgICAgICAgICAgICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVSb3coZGIsIHRhYmxlLCByb3dbJ3ZhbHVlcyddWzBdWyd2YWx1ZSddLCBsZW5ndGgpXG4gICAgICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0O1xuICAgICAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgICRzY29wZS5zaG93RGVsZXRlID0gZmFsc2U7XG4gICAgfVxuXG4gICAgJHNjb3BlLnNlbGVjdEFsbCA9IGZ1bmN0aW9uKGluc3RhbmNlQXJyYXkpIHtcbiAgICAgICAgaWYgKCRzY29wZS5zZWxlY3RlZEFsbCkge1xuICAgICAgICAgICAgaW5zdGFuY2VBcnJheS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgICAgIHJvdy5zZWxlY3RlZCA9IHRydWU7XG4gICAgICAgICAgICB9KVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgaW5zdGFuY2VBcnJheS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgICAgIHJvdy5zZWxlY3RlZCA9IGZhbHNlO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS51bmNoZWNrU2VsZWN0QWxsID0gZnVuY3Rpb24oaW5zdGFuY2VBcnJheSkge1xuICAgICAgICBpZiAoJHNjb3BlLnNlbGVjdGVkQWxsID09PSB0cnVlKSB7XG4gICAgICAgICAgICAkc2NvcGUuc2VsZWN0ZWRBbGwgPSBmYWxzZTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS5yZW1vdmVSb3cgPSBmdW5jdGlvbihkYiwgdGFibGUsIHJvdywgaW5zdGFuY2VBcnJheSkge1xuICAgICAgICB2YXIgbGVuZ3RoID0gaW5zdGFuY2VBcnJheS5sZW5ndGggLSAxO1xuICAgICAgICBUYWJsZUZhY3RvcnkucmVtb3ZlUm93KGRiLCB0YWJsZSwgcm93LCBsZW5ndGgpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgfSlcbiAgICB9XG5cbiAgICAkc2NvcGUucmVtb3ZlQ29sdW1uID0gZnVuY3Rpb24oZGIsIHRhYmxlLCBjb2x1bW5OYW1lKSB7XG4gICAgICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVDb2x1bW4oZGIsIHRhYmxlLCBjb2x1bW5OYW1lKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0O1xuICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICBDcmVhdGVDb2x1bW5zKCk7XG4gICAgICAgICAgICB9KVxuICAgIH1cblxuICAgICRzY29wZS5uZXdSb3cgPSBmdW5jdGlvbihkYiwgdGFibGUsIGFycikge1xuICAgICAgICB2YXIgYWxsSWRzID0gW107XG4gICAgICAgIGFyci5mb3JFYWNoKGZ1bmN0aW9uKHJvd0RhdGEpIHtcbiAgICAgICAgICAgIGFsbElkcy5wdXNoKHJvd0RhdGEudmFsdWVzWzBdLnZhbHVlKVxuICAgICAgICB9KVxuICAgICAgICB2YXIgc29ydGVkID0gYWxsSWRzLnNvcnQoZnVuY3Rpb24oYSwgYikge1xuICAgICAgICAgICAgcmV0dXJuIGIgLSBhXG4gICAgICAgIH0pXG4gICAgICAgIGlmIChzb3J0ZWQubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgVGFibGVGYWN0b3J5LmFkZFJvdyhkYiwgdGFibGUsIHNvcnRlZFswXSArIDEpXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHJlc3VsdDtcbiAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgIH0pXG5cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIFRhYmxlRmFjdG9yeS5hZGRSb3coZGIsIHRhYmxlLCAxKVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLmFkZENvbHVtbiA9IGZ1bmN0aW9uKGRiLCB0YWJsZSkge1xuICAgICAgICB2YXIgY29sTnVtcyA9ICRzY29wZS5jb2x1bW5zLmpvaW4oJyAnKS5tYXRjaCgvXFxkKy9nKTtcbiAgICAgICAgaWYgKGNvbE51bXMpIHtcbiAgICAgICAgICAgIHZhciBzb3J0ZWROdW1zID0gY29sTnVtcy5zb3J0KGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gYiAtIGFcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB2YXIgbnVtSW5OZXcgPSBOdW1iZXIoc29ydGVkTnVtc1swXSkgKyAxO1xuICAgICAgICAgICAgdmFyIG5hbWVOZXdDb2wgPSAnQ29sdW1uICcgKyBudW1Jbk5ldy50b1N0cmluZygpO1xuXG4gICAgICAgICAgICBUYWJsZUZhY3RvcnkuYWRkQ29sdW1uKGRiLCB0YWJsZSwgbmFtZU5ld0NvbClcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSgkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKVxuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24odGhlVGFibGUpIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gdGhlVGFibGVbMF07XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZUNvbHVtbnMoKTtcbiAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB2YXIgbmV4dENvbE51bSA9ICRzY29wZS5jb2x1bW5zLmxlbmd0aCArIDE7XG4gICAgICAgICAgICB2YXIgbmV3Q29sTmFtZSA9ICdDb2x1bW4gJyArIG5leHRDb2xOdW07XG4gICAgICAgICAgICBUYWJsZUZhY3RvcnkuYWRkQ29sdW1uKGRiLCB0YWJsZSwgJ0NvbHVtbiAxJylcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSgkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKVxuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24odGhlVGFibGUpIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gdGhlVGFibGVbMF07XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZUNvbHVtbnMoKTtcbiAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgIH1cblxuICAgIH1cblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9Pcmdhbml6aW5nIHN0dWZmIGludG8gYXJyYXlzLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuXG4gICAgLy8gR2V0IGFsbCBvZiB0aGUgY29sdW1ucyB0byBjcmVhdGUgdGhlIGNvbHVtbnMgb24gdGhlIGJvb3RzdHJhcCB0YWJsZVxuXG4gICAgZnVuY3Rpb24gQ3JlYXRlQ29sdW1ucygpIHtcbiAgICAgICAgJHNjb3BlLmNvbHVtbnMgPSBbXTtcbiAgICAgICAgJHNjb3BlLm9yaWdpbmFsQ29sVmFscyA9IFtdO1xuICAgICAgICB2YXIgdGFibGUgPSAkc2NvcGUuc2luZ2xlVGFibGVbMF07XG5cblxuICAgICAgICBmb3IgKHZhciBwcm9wIGluIHRhYmxlKSB7XG4gICAgICAgICAgICBpZiAocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jykge1xuICAgICAgICAgICAgICAgICRzY29wZS5jb2x1bW5zLnB1c2gocHJvcCk7XG4gICAgICAgICAgICAgICAgJHNjb3BlLm9yaWdpbmFsQ29sVmFscy5wdXNoKHByb3ApO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgQ3JlYXRlQ29sdW1ucygpO1xuXG4gICAgZnVuY3Rpb24gY3JlYXRlVmlydHVhbENvbHVtbnMoKSB7XG4gICAgICAgIGlmICgkc2NvcGUuYXNzb2NpYXRpb25zLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgICRzY29wZS52aXJ0dWFsQ29sdW1ucyA9IFtdO1xuICAgICAgICAgICAgJHNjb3BlLmFzc29jaWF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChyb3cuVGFibGUxID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmIHJvdy5SZWxhdGlvbnNoaXAxID09PSAnaGFzTWFueScpIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHZpcnR1YWwgPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5uYW1lID0gcm93LkFsaWFzMTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHJvdy5UaHJvdWdoKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLnRhYmxlID0gcm93LlRocm91Z2g7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLmNvbHVtbmtleSA9IHJvdy5BbGlhczE7XG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLnRhYmxlID0gcm93LlRhYmxlMjtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwuY29sdW1ua2V5ID0gcm93LkFsaWFzMjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAkc2NvcGUudmlydHVhbENvbHVtbnMucHVzaCh2aXJ0dWFsKTtcbiAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKHJvdy5UYWJsZTIgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgcm93LlJlbGF0aW9uc2hpcDIgPT09ICdoYXNNYW55Jykge1xuICAgICAgICAgICAgICAgICAgICB2YXIgdmlydHVhbCA9IHt9O1xuICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLm5hbWUgPSByb3cuQWxpYXMyO1xuICAgICAgICAgICAgICAgICAgICBpZiAocm93LlRocm91Z2gpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwudGFibGUgPSByb3cuVGhyb3VnaDtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwuY29sdW1ua2V5ID0gcm93LkFsaWFzMjtcbiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwudGFibGUgPSByb3cuVGFibGUxO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5jb2x1bW5rZXkgPSByb3cuQWxpYXMxO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS52aXJ0dWFsQ29sdW1ucy5wdXNoKHZpcnR1YWwpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBjcmVhdGVWaXJ0dWFsQ29sdW1ucygpO1xuXG4gICAgLy90aGlzIGZ1bmN0aW9uIHdpbGwgcmUgcnVuIHdoZW4gdGhlIGZpbHRlciBmdW5jdGlvbiBpcyBpbnZva2VkLCBpbiBvcmRlciB0byByZXBvcHVsYXRlIHRoZSB0YWJsZVxuICAgIGZ1bmN0aW9uIENyZWF0ZVJvd3MoKSB7XG4gICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5ID0gW107XG4gICAgICAgICRzY29wZS5zaW5nbGVUYWJsZS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgdmFyIHJvd1ZhbHVlcyA9IFtdO1xuICAgICAgICAgICAgdmFyIHJvd09iaiA9IHt9O1xuXG4gICAgICAgICAgICBmb3IgKHZhciBwcm9wIGluIHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKSByb3dWYWx1ZXMucHVzaCh7XG4gICAgICAgICAgICAgICAgICAgIGNvbDogcHJvcCxcbiAgICAgICAgICAgICAgICAgICAgdmFsdWU6IHJvd1twcm9wXVxuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByb3dPYmoudmFsdWVzID0gcm93VmFsdWVzO1xuICAgICAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkucHVzaChyb3dPYmopO1xuICAgICAgICB9KVxuICAgIH1cblxuICAgIC8vIFNvcnQgdGhlIHZhbHVlcyBpbiBzaW5nbGVUYWJsZSBzbyB0aGF0IGFsbCB0aGUgdmFsdWVzIGZvciBhIGdpdmVuIHJvdyBhcmUgZ3JvdXBlZFxuICAgIENyZWF0ZVJvd3MoKTtcbiAgICAvL3NlbmRzIHRoZSBmaWx0ZXJpbmcgcXVlcnkgYW5kIHRoZW4gcmUgcmVuZGVycyB0aGUgdGFibGUgd2l0aCBmaWx0ZXJlZCBkYXRhXG4gICAgJHNjb3BlLmZpbHRlciA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCBkYXRhKSB7XG4gICAgICAgIFRhYmxlRmFjdG9yeS5maWx0ZXIoZGJOYW1lLCB0YWJsZU5hbWUsIGRhdGEpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQuZGF0YTtcbiAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICB9KVxuICAgIH1cblxuXG4gICAgJHNjb3BlLmNoZWNrRm9yZWlnbiA9IGZ1bmN0aW9uKGNvbCkge1xuICAgICAgICByZXR1cm4gJHNjb3BlLmZvcmVpZ25Db2xzLmhhc093blByb3BlcnR5KGNvbCk7XG4gICAgfVxuXG4gICAgJHNjb3BlLmZpbmRQcmltYXJ5ID0gVGFibGVGYWN0b3J5LmZpbmRQcmltYXJ5O1xuXG4gICAgLy8qKioqKioqKioqKiogSW1wb3J0YW50ICoqKioqKioqKlxuICAgIC8vIE1ha2Ugc3VyZSB0byB1cGRhdGUgdGhlIHJvdyB2YWx1ZXMgQkVGT1JFIHRoZSBjb2x1bW4gbmFtZVxuICAgIC8vIFRoZSByb3dWYWxzVG9VcGRhdGUgYXJyYXkgc3RvcmVzIHRoZSB2YWx1ZXMgb2YgdGhlIE9SSUdJTkFMIGNvbHVtbiBuYW1lcyBzbyBpZiB0aGUgY29sdW1uIG5hbWUgaXMgdXBkYXRlZCBhZnRlciB0aGUgcm93IHZhbHVlLCB3ZSBzdGlsbCBoYXZlIHJlZmVyZW5jZSB0byB3aGljaCBjb2x1bW4gdGhlIHJvdyB2YWx1ZSByZWZlcmVuY2VzXG5cblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9VcGRhdGluZyBDb2x1bW4gU3R1ZmYvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG5cbiAgICAkc2NvcGUuY29sVmFsc1RvVXBkYXRlID0gW107XG5cbiAgICAkc2NvcGUudXBkYXRlQ29sdW1ucyA9IGZ1bmN0aW9uKG9sZCwgbmV3Q29sTmFtZSwgaSkge1xuICAgICAgICAkc2NvcGUuY29sdW1uc1tpXSA9IG5ld0NvbE5hbWU7XG5cbiAgICAgICAgdmFyIGNvbE9iaiA9IHsgb2xkVmFsOiAkc2NvcGUub3JpZ2luYWxDb2xWYWxzW2ldLCBuZXdWYWw6IG5ld0NvbE5hbWUgfTtcblxuICAgICAgICAvLyBpZiB0aGVyZSBpcyBub3RoaW5nIGluIHRoZSBhcnJheSB0byB1cGRhdGUsIHB1c2ggdGhlIHVwZGF0ZSBpbnRvIGl0XG4gICAgICAgIGlmICgkc2NvcGUuY29sVmFsc1RvVXBkYXRlLmxlbmd0aCA9PT0gMCkgeyAkc2NvcGUuY29sVmFsc1RvVXBkYXRlLnB1c2goY29sT2JqKTsgfSBlbHNlIHtcbiAgICAgICAgICAgIGZvciAodmFyIGUgPSAwOyBlIDwgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZS5sZW5ndGg7IGUrKykge1xuICAgICAgICAgICAgICAgIGlmICgkc2NvcGUuY29sVmFsc1RvVXBkYXRlW2VdLm9sZFZhbCA9PT0gY29sT2JqLm9sZFZhbCkge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuY29sVmFsc1RvVXBkYXRlW2VdID0gY29sT2JqO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZS5wdXNoKGNvbE9iaik7XG4gICAgICAgIH1cbiAgICAgICAgLy8gY2hlY2sgdG8gc2VlIGlmIHRoZSByb3cgaXMgYWxyZWFkeSBzY2hlZHVsZWQgdG8gYmUgdXBkYXRlZCwgaWYgaXQgaXMsIHRoZW4gdXBkYXRlIGl0IHdpdGggdGhlIG5ldyB0aGluZyB0byBiZSB1cGRhdGVkXG4gICAgfVxuXG4gICAgLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1VwZGF0aW5nIFJvdyBTdHVmZi8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgICRzY29wZS5yb3dWYWxzVG9VcGRhdGUgPSBbXTtcblxuICAgICRzY29wZS51cGRhdGVSb3cgPSBmdW5jdGlvbihvbGQsIG5ld0NlbGwsIHJvdywgaSwgail7XG4gICAgICAgIHZhciBjb2xzID0gJHNjb3BlLm9yaWdpbmFsQ29sVmFscztcbiAgICAgICAgdmFyIGZvdW5kID0gZmFsc2U7XG4gICAgICAgIHZhciBjb2xOYW1lID0gY29sc1tqXTtcbiAgICAgICAgZm9yKHZhciBrID0gMDsgayA8ICRzY29wZS5yb3dWYWxzVG9VcGRhdGUubGVuZ3RoOyBrKyspe1xuICAgICAgICAgICAgdmFyIG9iaiA9ICRzY29wZS5yb3dWYWxzVG9VcGRhdGVba107XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhvYmopXG4gICAgICAgICAgICBpZihvYmpbJ2lkJ10gPT09IGkpe1xuICAgICAgICAgICAgICAgIGZvdW5kID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICBpZihvYmpbY29sTmFtZV0pIG9ialtjb2xOYW1lXSA9IG5ld0NlbGw7XG4gICAgICAgICAgICAgICAgb2JqW2NvbE5hbWVdID0gbmV3Q2VsbDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBpZighZm91bmQpIHtcbiAgICAgICAgICAgIHZhciByb3dPYmogPSB7fTtcbiAgICAgICAgICAgIHJvd09ialsnaWQnXSA9IGk7XG4gICAgICAgICAgICByb3dPYmpbY29sTmFtZV0gPSBuZXdDZWxsO1xuICAgICAgICAgICAgJHNjb3BlLnJvd1ZhbHNUb1VwZGF0ZS5wdXNoKHJvd09iailcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS51cGRhdGVCYWNrZW5kID0gZnVuY3Rpb24oKSB7XG4gICAgICAgIHZhciBkYXRhID0geyByb3dzOiAkc2NvcGUucm93VmFsc1RvVXBkYXRlLCBjb2x1bW5zOiAkc2NvcGUuY29sVmFsc1RvVXBkYXRlIH1cbiAgICAgICAgVGFibGVGYWN0b3J5LnVwZGF0ZUJhY2tlbmQoJHNjb3BlLnRoZURiTmFtZSwgJHNjb3BlLnRoZVRhYmxlTmFtZSwgZGF0YSk7XG4gICAgfVxuXG5cbiAgICAkc2NvcGUuZGVsZXRlVGFibGUgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgVGFibGVGYWN0b3J5LmRlbGV0ZVRhYmxlKCRzY29wZS5jdXJyZW50VGFibGUpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAkc3RhdGUuZ28oJ1RhYmxlJywgeyBkYk5hbWU6ICRzY29wZS50aGVEYk5hbWUgfSwgeyByZWxvYWQ6IHRydWUgfSlcbiAgICAgICAgICAgIH0pXG4gICAgfVxuXG4gICAgLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1F1ZXJ5aW5nIFN0dWZmLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuXG4gICAgJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9ucyA9IFtdO1xuXG4gICAgJHNjb3BlLnRhYmxlc1RvUXVlcnkgPSBbXTtcblxuICAgIGFzc29jaWF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICBpZiAocm93LlRhYmxlMSA9PT0gJHNjb3BlLnRoZVRhYmxlTmFtZSAmJiAkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zLmluZGV4T2Yocm93LlRhYmxlMikgPT0gLTEpIHtcbiAgICAgICAgICAgICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMucHVzaChyb3cuVGFibGUyKTtcbiAgICAgICAgfSBlbHNlIGlmIChyb3cuVGFibGUyID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMuaW5kZXhPZihyb3cuVGFibGUxKSA9PSAtMSkge1xuICAgICAgICAgICAgJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9ucy5wdXNoKHJvdy5UYWJsZTEpO1xuICAgICAgICB9XG4gICAgfSlcblxuICAgICRzY29wZS5nZXRBc3NvY2lhdGVkID0gZnVuY3Rpb24odmFsKSB7XG4gICAgICAgIGlmICgkc2NvcGUudGFibGVzVG9RdWVyeS5pbmRleE9mKCRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnNbdmFsXSkgPT09IC0xKSB7XG4gICAgICAgICAgICAkc2NvcGUudGFibGVzVG9RdWVyeS5wdXNoKCRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnNbdmFsXSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHZhciBpID0gJHNjb3BlLnRhYmxlc1RvUXVlcnkuaW5kZXhPZigkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zW3ZhbF0pO1xuICAgICAgICAgICAgJHNjb3BlLnRhYmxlc1RvUXVlcnkuc3BsaWNlKGksIDEpXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAkc2NvcGUuY29sdW1uc0ZvclF1ZXJ5ID0gW107XG5cbiAgICAkc2NvcGUuZ2V0Q29sdW1uc0ZvclRhYmxlID0gZnVuY3Rpb24oKSB7XG4gICAgICAgIHZhciBwcm9taXNlc0ZvckNvbHVtbnMgPSBbXTtcbiAgICAgICAgJHNjb3BlLnRhYmxlc1RvUXVlcnkuZm9yRWFjaChmdW5jdGlvbih0YWJsZU5hbWUpIHtcbiAgICAgICAgICAgIHJldHVybiBwcm9taXNlc0ZvckNvbHVtbnMucHVzaChUYWJsZUZhY3RvcnkuZ2V0Q29sdW1uc0ZvclRhYmxlKCRzY29wZS50aGVEYk5hbWUsIHRhYmxlTmFtZSkpXG4gICAgICAgIH0pXG4gICAgICAgIFByb21pc2UuYWxsKHByb21pc2VzRm9yQ29sdW1ucylcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKGNvbHVtbnMpIHtcbiAgICAgICAgICAgICAgICBjb2x1bW5zLmZvckVhY2goZnVuY3Rpb24oY29sdW1uKSB7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5jb2x1bW5zRm9yUXVlcnkucHVzaChjb2x1bW4pO1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuJGV2YWxBc3luYygpXG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIH0pXG5cbiAgICB9XG5cbiAgICB2YXIgc2VsZWN0ZWRDb2x1bW5zID0ge307XG4gICAgdmFyIHF1ZXJ5VGFibGU7XG5cbiAgICAkc2NvcGUuZ2V0RGF0YUZyb21Db2x1bW5zID0gZnVuY3Rpb24odmFsKSB7XG4gICAgICAgIGlmKCFzZWxlY3RlZENvbHVtbnMpIHNlbGVjdGVkQ29sdW1ucyA9IFtdO1xuXG4gICAgICAgIHZhciBjb2x1bW5OYW1lID0gJHNjb3BlLmNvbHVtbnNGb3JRdWVyeVswXVsnY29sdW1ucyddW3ZhbC5pXTtcbiAgICAgICAgdmFyIHRhYmxlTmFtZSA9IHZhbC50YWJsZU5hbWVcbiAgICAgICAgcXVlcnlUYWJsZSA9IHRhYmxlTmFtZTtcblxuICAgICAgICBpZiAoIXNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdKSBzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXSA9IFtdO1xuICAgICAgICBpZiAoc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0uaW5kZXhPZihjb2x1bW5OYW1lKSAhPT0gLTEpIHtcbiAgICAgICAgICAgIHNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdLnNwbGljZShzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXS5pbmRleE9mKGNvbHVtbk5hbWUpLCAxKVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0ucHVzaChjb2x1bW5OYW1lKTtcbiAgICAgICAgfVxuICAgICAgICAkc2NvcGUuc2VsZWN0ZWRDb2x1bW5zID0gc2VsZWN0ZWRDb2x1bW5zO1xuICAgIH1cblxuXG4gICAgLy8gUnVubmluZyB0aGUgcXVlcnkgKyByZW5kZXJpbmcgdGhlIHF1ZXJ5XG4gICAgJHNjb3BlLnJlc3VsdE9mUXVlcnkgPSBbXTtcblxuICAgICRzY29wZS5xdWVyeVJlc3VsdDtcblxuICAgICRzY29wZS5hcnIgPSBbXTtcblxuXG4gICAgLy8gdGhlVGFibGVOYW1lXG5cbiAgICAkc2NvcGUucnVuSm9pbiA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAvLyBkYk5hbWUsIHRhYmxlMSwgYXJyYXlPZlRhYmxlcywgc2VsZWN0ZWRDb2x1bW5zLCBhc3NvY2lhdGlvbnNcbiAgICAgICAgdmFyIGNvbHVtbnNUb1JldHVybiA9ICRzY29wZS5jb2x1bW5zLm1hcChmdW5jdGlvbihjb2xOYW1lKXtcbiAgICAgICAgICAgIHJldHVybiAkc2NvcGUudGhlVGFibGVOYW1lICsgJy4nICsgY29sTmFtZTtcbiAgICAgICAgfSlcbiAgICAgICAgZm9yKHZhciBwcm9wIGluICRzY29wZS5zZWxlY3RlZENvbHVtbnMpe1xuICAgICAgICAgICAkc2NvcGUuc2VsZWN0ZWRDb2x1bW5zW3Byb3BdLmZvckVhY2goZnVuY3Rpb24oY29sKXtcbiAgICAgICAgICAgICAgICBjb2x1bW5zVG9SZXR1cm4ucHVzaChwcm9wICsgJy4nICsgY29sKVxuICAgICAgICAgICB9KVxuICAgICAgICB9XG4gICAgICAgIFRhYmxlRmFjdG9yeS5ydW5Kb2luKCRzY29wZS50aGVEYk5hbWUsICRzY29wZS50aGVUYWJsZU5hbWUsICRzY29wZS50YWJsZXNUb1F1ZXJ5LCAkc2NvcGUuc2VsZWN0ZWRDb2x1bW5zLCAkc2NvcGUuYXNzb2NpYXRpb25zLCBjb2x1bW5zVG9SZXR1cm4pXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihxdWVyeVJlc3VsdCkge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKCdRVUVSWVJSRVNVTFQnLCBxdWVyeVJlc3VsdCk7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnF1ZXJ5UmVzdWx0ID0gcXVlcnlSZXN1bHQ7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgJHN0YXRlLmdvKCdUYWJsZS5TaW5nbGUucXVlcnknKTtcbiAgICAgICAgICAgIH0pXG4gICAgfVxuXG4gICAgJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkID0gdHJ1ZTtcblxuICAgICRzY29wZS5vcGVuID0gZnVuY3Rpb24gKGRiTmFtZSwgdGJsTmFtZSwgY29sLCBpbmRleCkge1xuXG4gICAgICB2YXIgbW9kYWxJbnN0YW5jZSA9ICR1aWJNb2RhbC5vcGVuKHtcbiAgICAgICAgYW5pbWF0aW9uOiAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQsXG4gICAgICAgIGJhY2tkcm9wOiBmYWxzZSxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9hc3NvY2lhdGlvbi5tb2RhbC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0Fzc29jaWF0aW9uSW5zdGFuY2VDdHJsJyxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICAgIGZvcmVpZ25Db2xzOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gJHNjb3BlLmZvcmVpZ25Db2xzO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgZm9yVGFibGU6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSl7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyh0YmxOYW1lKVxuICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5maW5kUHJpbWFyeShkYk5hbWUsIHRibE5hbWUpO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgZm9yVGFibGVOYW1lOiBmdW5jdGlvbigpe1xuICAgICAgICAgICAgcmV0dXJuIHRibE5hbWU7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBjdXJyVGFibGU6IGZ1bmN0aW9uKCl7XG4gICAgICAgICAgICByZXR1cm4gJHNjb3BlLnRoZVRhYmxlTmFtZVxuICAgICAgICAgIH0sXG4gICAgICAgICAgY29sTmFtZTogZnVuY3Rpb24gKCl7XG4gICAgICAgICAgICByZXR1cm4gY29sO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgaWQxOiBmdW5jdGlvbigpe1xuICAgICAgICAgICAgcmV0dXJuIGluZGV4O1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfSk7XG5cbiAgICAgIG1vZGFsSW5zdGFuY2UucmVzdWx0LnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICBjb25zb2xlLmxvZyhcIkNMT1NFRFwiKVxuICAgICAgICAkc2NvcGUuJGV2YWxBc3luYygpO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgICRzY29wZS50b2dnbGVBbmltYXRpb24gPSBmdW5jdGlvbiAoKSB7XG4gICAgICAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQgPSAhJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkO1xuICAgIH07XG5cbiAgICAkc2NvcGUuZmlsdGVyZWRSb3dzPVtdO1xuICAgICRzY29wZS5jdXJyZW50UGFnZT0xO1xuICAgICRzY29wZS5udW1QZXJQYWdlPTEwO1xuICAgICRzY29wZS5tYXhTaXplPTU7XG5cbiAgICAkc2NvcGUuJHdhdGNoKFwiY3VycmVudFBhZ2UgKyBudW1QZXJQYWdlXCIsIGZ1bmN0aW9uKCl7XG4gICAgICAgIHZhciBiZWdpbiA9ICgoJHNjb3BlLmN1cnJlbnRQYWdlIC0gMSkgKiAkc2NvcGUubnVtUGVyUGFnZSk7XG4gICAgICAgIHZhciBlbmQgPSBiZWdpbiArICRzY29wZS5udW1QZXJQYWdlO1xuICAgICAgICAkc2NvcGUuZmlsdGVyZWRSb3dzID0gJHNjb3BlLmluc3RhbmNlQXJyYXkuc2xpY2UoYmVnaW4sIGVuZCk7XG4gICAgfSlcblxuICAgICRzY29wZS4kd2F0Y2goXCJpbnN0YW5jZUFycmF5XCIsIGZ1bmN0aW9uKCl7XG4gICAgICAgIHZhciBiZWdpbiA9ICgoJHNjb3BlLmN1cnJlbnRQYWdlIC0gMSkgKiAkc2NvcGUubnVtUGVyUGFnZSk7XG4gICAgICAgIHZhciBlbmQgPSBiZWdpbiArICRzY29wZS5udW1QZXJQYWdlO1xuICAgICAgICAkc2NvcGUuZmlsdGVyZWRSb3dzID0gJHNjb3BlLmluc3RhbmNlQXJyYXkuc2xpY2UoYmVnaW4sIGVuZCk7XG4gICAgfSlcblxuICAgICRzY29wZS5jc3YgPSBmdW5jdGlvbih0YWJsZSl7XG4gICAgICAgIGFsYXNxbChcIlNFTEVDVCAqIElOVE8gQ1NWKCdteWRhdGEuY3N2Jywge2hlYWRlcnM6dHJ1ZX0pIEZST00gP1wiLFt0YWJsZV0pO1xuICAgIH0gICAgXG5cbn0pO1xuIiwiYXBwLmNvbnRyb2xsZXIoJ1RhYmxlQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsIGFsbFRhYmxlcywgJHN0YXRlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgJHVpYk1vZGFsLCBIb21lRmFjdG9yeSwgYXNzb2NpYXRpb25zLCBhbGxDb2x1bW5zKSB7XG5cblx0JHNjb3BlLmFsbFRhYmxlcyA9IGFsbFRhYmxlcztcblxuXHQkc2NvcGUuY29sdW1uQXJyYXkgPSBbXTtcblxuXHQkc2NvcGUuZGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZVxuXG5cdCRzY29wZS5hc3NvY2lhdGlvbnMgPSBhc3NvY2lhdGlvbnM7XG5cblx0JHNjb3BlLmFsbENvbHVtbnMgPSBhbGxDb2x1bW5zO1xuXG5cdCRzY29wZS5hc3NvY2lhdGlvblRhYmxlID0gJHN0YXRlUGFyYW1zLmRiTmFtZSArICdfYXNzb2MnO1xuXG5cdCRzY29wZS5udW1UYWJsZXMgPSAkc2NvcGUuYWxsVGFibGVzLnJvd3MubGVuZ3RoO1xuXG5cdCRzY29wZS5hZGQgPSBmdW5jdGlvbigpIHtcblx0XHQkc2NvcGUuY29sdW1uQXJyYXkucHVzaCgnMScpO1xuXHR9XG5cblx0JHNjb3BlLiRzdGF0ZSA9ICRzdGF0ZTsgXHQvLyB1c2VkIHRvIGhpZGUgdGhlIGxpc3Qgb2YgYWxsIHRhYmxlcyB3aGVuIGluIHNpbmdsZSB0YWJsZSBzdGF0ZVxuXG5cdCRzY29wZS5hc3NvY2lhdGlvblR5cGVzID0gWydoYXNPbmUnLCAnaGFzTWFueSddO1xuXG5cdCRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lO1xuXG5cdCRzY29wZS5zdWJtaXR0ZWQgPSBmYWxzZTtcblxuXHQkc2NvcGUubWFrZUFzc29jaWF0aW9ucyA9IGZ1bmN0aW9uKGFzc29jaWF0aW9uLCBkYk5hbWUpIHtcblx0XHQkc2NvcGUuc3VibWl0dGVkID0gdHJ1ZTtcblx0XHRUYWJsZUZhY3RvcnkubWFrZUFzc29jaWF0aW9ucyhhc3NvY2lhdGlvbiwgZGJOYW1lKVxuXHR9IFxuXG5cdCRzY29wZS53aGVyZWJldHdlZW4gPSBmdW5jdGlvbihjb25kaXRpb24pIHtcblx0XHRpZihjb25kaXRpb24gPT09IFwiV0hFUkUgQkVUV0VFTlwiIHx8IGNvbmRpdGlvbiA9PT0gXCJXSEVSRSBOT1QgQkVUV0VFTlwiKSByZXR1cm4gdHJ1ZTtcblx0fVxuXG5cdCRzY29wZS5jcmVhdGVUYWJsZSA9IGZ1bmN0aW9uKHRhYmxlKXtcblx0XHRUYWJsZUZhY3RvcnkuY3JlYXRlVGFibGUodGFibGUpXG5cdFx0LnRoZW4oZnVuY3Rpb24oKXtcblx0XHRcdCRzdGF0ZS5nbygnVGFibGUnLCB7ZGJOYW1lOiAkc2NvcGUuZGJOYW1lfSwge3JlbG9hZDogdHJ1ZX0pO1xuXHRcdH0pXG5cdH1cblxuXHQkc2NvcGUuY29sdW1uRGF0YVR5cGUgPSBmdW5jdGlvbigpIHtcblx0XHQkc2NvcGUuYWxsQ29sdW1ucy5mb3JFYWNoKGZ1bmN0aW9uKG9iaikge1xuXHRcdFx0aWYob2JqLnRhYmxlX25hbWUgPT09ICRzY29wZS5xdWVyeS50YWJsZTEgJiYgb2JqLmNvbHVtbl9uYW1lID09PSAkc2NvcGUucXVlcnkuY29sdW1uKSAkc2NvcGUudHlwZSA9IG9iai5kYXRhX3R5cGU7XG5cdFx0fSlcblx0fVxuXG5cdCRzY29wZS5zZWxlY3RlZEFzc29jID0ge307XG5cblx0JHNjb3BlLnN1Ym1pdFF1ZXJ5ID0gVGFibGVGYWN0b3J5LnN1Ym1pdFF1ZXJ5O1xuXG5cdCRzY29wZS5hc3NvY3RhYmxlID0gZnVuY3Rpb24gKHRhYmxlTmFtZSl7XG5cdFx0cmV0dXJuIHRhYmxlTmFtZSA9PT0gJHN0YXRlUGFyYW1zLmRiTmFtZStcIl9hc3NvY1wiO1xuXHR9XG5cbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ1RhYmxlRmFjdG9yeScsIGZ1bmN0aW9uICgkaHR0cCwgJHN0YXRlUGFyYW1zKSB7XG5cblx0dmFyIFRhYmxlRmFjdG9yeSA9IHt9O1xuXG5cdGZ1bmN0aW9uIHJlc1RvRGF0YShyZXMpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5kYXRhO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRBbGxUYWJsZXMgPSBmdW5jdGlvbihkYk5hbWUpe1xuICAgIFx0cmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lKVxuICAgIFx0LnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldERiTmFtZSA9IGZ1bmN0aW9uKGRiTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvbWFzdGVyZGIvJyArIGRiTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5maWx0ZXIgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgZGF0YSkge1xuICAgICAgICByZXR1cm4gJGh0dHAucHV0KCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnL2ZpbHRlcicsIGRhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LnVwZGF0ZUJhY2tlbmQgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgZGF0YSkge1xuICAgICAgICByZXR1cm4gJGh0dHAucHV0KCdhcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSwgZGF0YSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuYWRkUm93ID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIHJvd051bWJlcikge1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnYXBpL2NsaWVudGRiL2FkZHJvdy8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lLCB7cm93TnVtYmVyOiByb3dOdW1iZXJ9KVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVSb3cgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgcm93SWQsIGxlbmd0aCl7XG4gICAgICAgIHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSArICcvJyArIHJvd0lkICsgJy8nICsgbGVuZ3RoKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LnJlbW92ZUNvbHVtbiA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCBjb2x1bW5OYW1lKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmRlbGV0ZSgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lICsgJy9jb2x1bW4vJyArIGNvbHVtbk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuYWRkQ29sdW1uID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIG51bU5ld0NvbCl7XG4gICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCdhcGkvY2xpZW50ZGIvYWRkY29sdW1uLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnLycgKyBudW1OZXdDb2wpXG4gICAgfVxuICAgIFRhYmxlRmFjdG9yeS5jcmVhdGVUYWJsZSA9IGZ1bmN0aW9uKHRhYmxlKXtcbiAgICAgICAgdGFibGUuZGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZTtcbiAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9hcGkvY2xpZW50ZGInLCB0YWJsZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZGVsZXRlVGFibGUgPSBmdW5jdGlvbihjdXJyZW50VGFibGUpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmRlbGV0ZSgnL2FwaS9jbGllbnRkYi8nICsgY3VycmVudFRhYmxlLmRiTmFtZSArICcvJyArIGN1cnJlbnRUYWJsZS50YWJsZU5hbWUpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5Lm1ha2VBc3NvY2lhdGlvbnMgPSBmdW5jdGlvbihhc3NvY2lhdGlvbiwgZGJOYW1lKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnL2Fzc29jaWF0aW9uJywgYXNzb2NpYXRpb24pXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmRlbGV0ZURiID0gZnVuY3Rpb24oZGJOYW1lKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZ2V0QXNzb2NpYXRpb25zID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi9hc3NvY2lhdGlvbnRhYmxlLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgIFRhYmxlRmFjdG9yeS5nZXRBbGxBc3NvY2lhdGlvbnMgPSBmdW5jdGlvbihkYk5hbWUpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi9hbGxhc3NvY2lhdGlvbnMvJyArIGRiTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZ2V0QWxsQ29sdW1ucyA9IGZ1bmN0aW9uKGRiTmFtZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2NsaWVudGRiL2dldGFsbGNvbHVtbnMvJyArIGRiTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZ2V0Q29sdW1uc0ZvclRhYmxlID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2NsaWVudGRiL2NvbHVtbnNmb3J0YWJsZS8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5ydW5Kb2luID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZTEsIGFycmF5T2ZUYWJsZXMsIHNlbGVjdGVkQ29sdW1ucywgYXNzb2NpYXRpb25zLCBjb2xzVG9SZXR1cm4pIHtcbiAgICAgICAgdmFyIGRhdGEgPSB7fTtcbiAgICAgICAgZGF0YS5kYk5hbWUgPSBkYk5hbWU7XG4gICAgICAgIGRhdGEudGFibGUyID0gYXJyYXlPZlRhYmxlc1swXTtcbiAgICAgICAgZGF0YS5hcnJheU9mVGFibGVzID0gYXJyYXlPZlRhYmxlcztcbiAgICAgICAgZGF0YS5zZWxlY3RlZENvbHVtbnMgPSBzZWxlY3RlZENvbHVtbnM7XG4gICAgICAgIGRhdGEuY29sc1RvUmV0dXJuID0gY29sc1RvUmV0dXJuO1xuXG4gICAgICAgIC8vIFtoYXNNYW55LCBoYXNPbmUsIGhhc01hbnkgcHJpbWFyeSBrZXksIGhhc09uZSBmb3JnZWluIGtleV1cblxuICAgICAgICBhc3NvY2lhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIGlmKHJvdy5UYWJsZTEgPT09IHRhYmxlMSAmJiByb3cuVGFibGUyID09PSBkYXRhLnRhYmxlMil7XG4gICAgICAgICAgICAgICAgZGF0YS5hbGlhcyA9IHJvdy5BbGlhczE7XG4gICAgICAgICAgICAgICAgaWYocm93LlJlbGF0aW9uc2hpcDEgPT09ICdoYXNPbmUnKXtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTEgPSByb3cuVGFibGUyO1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMiA9IHJvdy5UYWJsZTE7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2V7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUxID0gcm93LlRhYmxlMTtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTIgPSByb3cuVGFibGUyOyAgIFxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2UgaWYocm93LlRhYmxlMSA9PT0gZGF0YS50YWJsZTIgJiYgcm93LlRhYmxlMiA9PT0gdGFibGUxKXtcbiAgICAgICAgICAgICAgICBkYXRhLmFsaWFzID0gcm93LkFsaWFzMTtcbiAgICAgICAgICAgICAgICBpZihyb3cuUmVsYXRpb25zaGlwMSA9PT0gJ2hhc01hbnknKXtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTEgPSByb3cuVGFibGUxO1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMiA9IHJvdy5UYWJsZTI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2V7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUxID0gcm93LlRhYmxlMjtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTIgPSByb3cuVGFibGUxOyAgIFxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfSlcblxuICAgICAgICBjb25zb2xlLmxvZygnREFUQScsZGF0YSk7XG5cbiAgICAgICAgcmV0dXJuICRodHRwLnB1dCgnL2FwaS9jbGllbnRkYi9ydW5qb2luJywgZGF0YSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZ2V0UHJpbWFyeUtleXMgPSBmdW5jdGlvbihpZCwgZGJOYW1lLCB0YWJsZU5hbWUsIGNvbHVtbmtleSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSArICcvJyArIGlkICsgXCIvXCIgKyBjb2x1bW5rZXkpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmZpbmRQcmltYXJ5ID0gZnVuY3Rpb24oZGJOYW1lLCB0YmxOYW1lKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi9wcmltYXJ5LycrZGJOYW1lKycvJyt0YmxOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5zZXRGb3JlaWduS2V5ID0gZnVuY3Rpb24oZGJOYW1lLCB0YmxOYW1lLCBjb2xOYW1lLCBpZDEsIGlkMil7XG4gICAgICAgIHZhciBkYXRhID0ge307XG4gICAgICAgIGRhdGEuZGJOYW1lID0gZGJOYW1lO1xuICAgICAgICBkYXRhLnRibE5hbWUgPSB0YmxOYW1lO1xuICAgICAgICBkYXRhLmNvbE5hbWUgPSBjb2xOYW1lO1xuICAgICAgICBkYXRhLmlkMSA9IGlkMTtcbiAgICAgICAgZGF0YS5pZDIgPSBpZDI7XG5cbiAgICAgICAgcmV0dXJuICRodHRwLnB1dCgnL2FwaS9jbGllbnRkYi9zZXRGb3JlaWduS2V5JywgZGF0YSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTsgICBcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkudXBkYXRlSm9pblRhYmxlID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIGlkLCBuZXdSb3csIHRhYmxlVG9VcGRhdGUsIGNvbHVtbk5hbWUpIHtcbiAgICAgICAgdmFyIGRhdGEgPSB7fTtcbiAgICAgICAgZGF0YS5kYk5hbWUgPSBkYk5hbWU7XG4gICAgICAgIGRhdGEudGJsTmFtZSA9IHRhYmxlTmFtZTtcbiAgICAgICAgZGF0YS5yb3dJZCA9IGlkO1xuICAgICAgICBkYXRhLm5ld1JvdyA9IG5ld1JvdztcbiAgICAgICAgZGF0YS50YWJsZVRvVXBkYXRlID0gdGFibGVUb1VwZGF0ZTtcbiAgICAgICAgZGF0YS5jb2x1bW5OYW1lID0gY29sdW1uTmFtZTtcbiAgICAgICBcbiAgICAgICByZXR1cm4gJGh0dHAucHV0KCcvYXBpL2NsaWVudGRiL3VwZGF0ZUpvaW5UYWJsZScsIGRhdGEpXG4gICAgICAgLnRoZW4ocmVzVG9EYXRhKTsgIFxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5pbmNyZW1lbnQgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAucHV0KCcvYXBpL2NsaWVudGRiLycrIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSArJy9hZGRyb3dvbmpvaW4nKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuXHRyZXR1cm4gVGFibGVGYWN0b3J5OyBcbn0pIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUnLCB7XG4gICAgICAgIHVybDogJy86ZGJOYW1lJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS90YWJsZS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1RhYmxlQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgXHRhbGxUYWJsZXM6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRBbGxUYWJsZXMoJHN0YXRlUGFyYW1zLmRiTmFtZSk7XG4gICAgICAgIFx0fSwgXG4gICAgICAgICAgICBhc3NvY2lhdGlvbnM6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRBbGxBc3NvY2lhdGlvbnMoJHN0YXRlUGFyYW1zLmRiTmFtZSk7XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgYWxsQ29sdW1uczogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldEFsbENvbHVtbnMoJHN0YXRlUGFyYW1zLmRiTmFtZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KTtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5TaW5nbGUnLCB7XG4gICAgICAgIHVybDogJy86dGFibGVOYW1lJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9zaW5nbGV0YWJsZS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1NpbmdsZVRhYmxlQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICAgIHNpbmdsZVRhYmxlOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0U2luZ2xlVGFibGUoJHN0YXRlUGFyYW1zLmRiTmFtZSwgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSk7XG4gICAgICAgICAgICB9LCBcbiAgICAgICAgICAgIGFzc29jaWF0aW9uczogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldEFzc29jaWF0aW9ucygkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pO1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlLkpvaW4nLCB7XG4gICAgICAgIHVybDogJy86dGFibGVOYW1lLzpyb3dJZC86a2V5L2pvaW4nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL2pvaW4uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdKb2luVGFibGVDdHJsJyxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICAgICAgam9pblRhYmxlOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0UHJpbWFyeUtleXMoJHN0YXRlUGFyYW1zLnJvd0lkLCAkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lLCAkc3RhdGVQYXJhbXMua2V5KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pO1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlLlRocm91Z2gnLCB7XG4gICAgICAgIHVybDogJy86dGFibGVOYW1lL3Rocm91Z2gnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL3Rocm91Z2guaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdUaHJvdWdoQ3RybCcsIFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgICBzaW5nbGVUYWJsZTogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldFNpbmdsZVRhYmxlKCRzdGF0ZVBhcmFtcy5kYk5hbWUsICRzdGF0ZVBhcmFtcy50YWJsZU5hbWUpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSk7ICBcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5jcmVhdGUnLCB7XG4gICAgICAgIHVybDogJy9jcmVhdGV0YWJsZScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvY3JlYXRldGFibGUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdUYWJsZUN0cmwnXG4gICAgfSk7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUuc2V0QXNzb2NpYXRpb24nLCB7XG4gICAgICAgIHVybDogJy9zZXRhc3NvY2lhdGlvbicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvc2V0YXNzb2NpYXRpb24uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdUYWJsZUN0cmwnXG4gICAgfSk7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUuU2luZ2xlLnF1ZXJ5Jywge1xuICAgICAgICB1cmw6ICcvcXVlcnlyZXN1bHQnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL3F1ZXJ5Lmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnUXVlcnlUYWJsZUN0cmwnXG4gICAgfSk7ICAgICBcblxuXG59KTsiLCJhcHAuY29udHJvbGxlcignVGhyb3VnaEN0cmwnLCBmdW5jdGlvbigkc2NvcGUsIFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zLCBhc3NvY2lhdGlvbnMsIHNpbmdsZVRhYmxlLCAkdWliTW9kYWwpIHtcblxuICAgICRzY29wZS5hc3NvY2lhdGlvbnMgPSBhc3NvY2lhdGlvbnM7XG4gICAgJHNjb3BlLnR3b1RhYmxlcyA9IFtdO1xuICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHNpbmdsZVRhYmxlWzBdO1xuICAgICRzY29wZS50aGVEYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lO1xuICAgICRzY29wZS50YWJsZU5hbWUgPSAkc3RhdGVQYXJhbXMudGFibGVOYW1lO1xuXG4gICAgZnVuY3Rpb24gZ2V0MlRhYmxlcygpIHtcbiAgICAgICAgJHNjb3BlLmFzc29jaWF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKGFzc29jKSB7XG4gICAgICAgICAgICBpZiAoYXNzb2NbJ1Rocm91Z2gnXSA9PT0gJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSkge1xuICAgICAgICAgICAgICAgICRzY29wZS50d29UYWJsZXMucHVzaChhc3NvY1snVGFibGUxJ10pO1xuICAgICAgICAgICAgICAgICRzY29wZS50d29UYWJsZXMucHVzaChhc3NvY1snVGFibGUyJ10pOyAvL2hlcmUgLSBjb21lIGJhY2tcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSlcbiAgICB9XG5cbiAgICBnZXQyVGFibGVzKCk7XG5cbiAgICBmdW5jdGlvbiBDcmVhdGVDb2x1bW5zKCkge1xuICAgICAgICAkc2NvcGUuY29sdW1ucyA9IFtdO1xuICAgICAgICB2YXIgdGFibGUgPSBzaW5nbGVUYWJsZVswXVswXTtcbiAgICAgICAgZm9yICh2YXIgcHJvcCBpbiB0YWJsZSkge1xuICAgICAgICAgICAgJHNjb3BlLmNvbHVtbnMucHVzaChwcm9wKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIENyZWF0ZUNvbHVtbnMoKTtcblxuXG4gICAgLy90aGlzIGZ1bmN0aW9uIHdpbGwgcmUgcnVuIHdoZW4gdGhlIGZpbHRlciBmdW5jdGlvbiBpcyBpbnZva2VkLCBpbiBvcmRlciB0byByZXBvcHVsYXRlIHRoZSB0YWJsZVxuICAgIGZ1bmN0aW9uIENyZWF0ZVJvd3MoKSB7XG5cbiAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkgPSBbXTtcbiAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICB2YXIgcm93VmFsdWVzID0gW107XG4gICAgICAgICAgICBmb3IgKHZhciBwcm9wIGluIHJvdykge1xuICAgICAgICAgICAgICAgIHJvd1ZhbHVlcy5wdXNoKHJvd1twcm9wXSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5LnB1c2gocm93VmFsdWVzKVxuICAgICAgICB9KVxuICAgIH1cblxuICAgIC8vIFNvcnQgdGhlIHZhbHVlcyBpbiBzaW5nbGVUYWJsZSBzbyB0aGF0IGFsbCB0aGUgdmFsdWVzIGZvciBhIGdpdmVuIHJvdyBhcmUgZ3JvdXBlZFxuICAgIENyZWF0ZVJvd3MoKTtcblxuICAgIC8vICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9IHRydWU7XG5cbiAgICAkc2NvcGUub3BlbiA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCBpbmRleCwgcm93LCBjb2x1bW5OYW1lKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKGRiTmFtZSwgdGFibGVOYW1lLCBpbmRleCwgcm93LCBjb2x1bW5OYW1lKTtcbiAgICAgICAgdmFyIHRoZVRhYmxlID0gJHNjb3BlLnR3b1RhYmxlc1tpbmRleC0xXTtcbiAgICAgICAgY29uc29sZS5sb2coJ3R3b1RhYmxlcycsICRzY29wZS50d29UYWJsZXMpO1xuICAgICAgICBjb25zb2xlLmxvZygndGhlVGFibGUnLCB0aGVUYWJsZSk7XG5cbiAgICAgICAgdmFyIG1vZGFsSW5zdGFuY2UgPSAkdWliTW9kYWwub3Blbih7XG4gICAgICAgICAgICBhbmltYXRpb246ICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCxcbiAgICAgICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvdGhyb3VnaC5tb2RhbC5odG1sJyxcbiAgICAgICAgICAgIGNvbnRyb2xsZXI6ICdUaHJvdWdoTW9kYWxDdHJsJyxcbiAgICAgICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICAgICAgICB0aGVUYWJsZTogZnVuY3Rpb24oVGFibGVGYWN0b3J5KSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0U2luZ2xlVGFibGUoZGJOYW1lLCB0aGVUYWJsZSk7XG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB0YWJsZU5hbWUgOiBmdW5jdGlvbigpIHsgcmV0dXJuIHRoZVRhYmxlIH0sXG4gICAgICAgICAgICAgICAgcm93SWQgOiBmdW5jdGlvbigpIHsgcmV0dXJuIHJvdyB9LFxuICAgICAgICAgICAgICAgIGNvbHVtbk5hbWUgOiBmdW5jdGlvbigpIHsgcmV0dXJuIGNvbHVtbk5hbWUgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcblxuICAgICAgICBtb2RhbEluc3RhbmNlLnJlc3VsdC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJDTE9TRURcIilcbiAgICAgICAgICAgICRzY29wZS4kZXZhbEFzeW5jKCk7XG4gICAgICAgIH0pO1xuICAgIH07XG5cbiAgICAkc2NvcGUudG9nZ2xlQW5pbWF0aW9uID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9ICEkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQ7XG4gICAgfTtcblxuICAgICRzY29wZS5uZXdSb3cgPSBmdW5jdGlvbihkYiwgdGFibGUpIHtcbiAgICAgICBUYWJsZUZhY3RvcnkuaW5jcmVtZW50KGRiLCB0YWJsZSlcbiAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgY29uc29sZS5sb2cocmVzdWx0KTtcbiAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkgPSByZXN1bHQ7XG4gICAgICAgICRzY29wZS4kZXZhbEFzeW5jKCk7XG4gICAgICAgfSlcbiAgICB9XG5cbiAgICAvL2RlbGV0ZSBhIHJvdyBcbiAgICAkc2NvcGUuc2hvd0RlbGV0ZSA9IGZhbHNlO1xuICAgICRzY29wZS50b2dnbGVEZWxldGUgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgJHNjb3BlLnNob3dEZWxldGUgPSAhJHNjb3BlLnNob3dEZWxldGVcbiAgICB9XG5cbiAgICAkc2NvcGUuZGVsZXRlU2VsZWN0ZWQgPSBmdW5jdGlvbihkYiwgdGFibGUsIGluc3RhbmNlQXJyYXkpIHtcbiAgICAgICAgaW5zdGFuY2VBcnJheS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgaWYgKHJvdy5zZWxlY3RlZCkge1xuICAgICAgICAgICAgICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVSb3coZGIsIHRhYmxlLCByb3dbMF0pXG4gICAgICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0O1xuICAgICAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgfVxuICAgICAgICB9KVxuICAgICAgICAkc2NvcGUuc2hvd0RlbGV0ZSA9IGZhbHNlO1xuICAgIH1cblxuICAgICRzY29wZS5zZWxlY3RBbGwgPSBmdW5jdGlvbihpbnN0YW5jZUFycmF5KSB7XG4gICAgICAgIGlmICgkc2NvcGUuc2VsZWN0ZWRBbGwpIHtcbiAgICAgICAgICAgIGluc3RhbmNlQXJyYXkuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgICAgICByb3cuc2VsZWN0ZWQgPSB0cnVlO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGluc3RhbmNlQXJyYXkuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgICAgICByb3cuc2VsZWN0ZWQgPSBmYWxzZTtcbiAgICAgICAgICAgIH0pXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAkc2NvcGUudW5jaGVja1NlbGVjdEFsbCA9IGZ1bmN0aW9uKGluc3RhbmNlQXJyYXkpIHtcbiAgICAgICAgaWYgKCRzY29wZS5zZWxlY3RlZEFsbCA9PT0gdHJ1ZSkge1xuICAgICAgICAgICAgJHNjb3BlLnNlbGVjdGVkQWxsID0gZmFsc2U7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAkc2NvcGUucmVtb3ZlUm93ID0gZnVuY3Rpb24oZGIsIHRhYmxlLCByb3cpIHtcbiAgICAgICAgVGFibGVGYWN0b3J5LnJlbW92ZVJvdyhkYiwgdGFibGUsIHJvdylcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHJlc3VsdDtcbiAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICB9KVxuICAgIH1cblxuICAgICRzY29wZS5jc3YgPSBmdW5jdGlvbih0YWJsZSl7XG4gICAgICAgIGFsYXNxbChcIlNFTEVDVCAqIElOVE8gQ1NWKCdteWRhdGEuY3N2Jywge2hlYWRlcnM6dHJ1ZX0pIEZST00gP1wiLFt0YWJsZV0pO1xuICAgIH0gICAgXG5cbn0pXG4iLCJhcHAuY29udHJvbGxlcignVGhyb3VnaE1vZGFsQ3RybCcsIGZ1bmN0aW9uKCRzY29wZSwgJHVpYk1vZGFsSW5zdGFuY2UsIFRhYmxlRmFjdG9yeSwgSG9tZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgJHN0YXRlLCB0aGVUYWJsZSwgdGFibGVOYW1lLCByb3dJZCwgY29sdW1uTmFtZSkge1xuXG4gICAgJHNjb3BlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG5cbiAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSB0aGVUYWJsZTtcblxuICAgICRzY29wZS50YWJsZU5hbWUgPSB0YWJsZU5hbWU7XG5cbiAgICAkc2NvcGUucm93SWQgPSByb3dJZDtcblxuICAgICRzY29wZS5jb2x1bW5OYW1lID0gY29sdW1uTmFtZTtcblxuICAgICRzY29wZS5zZXRTZWxlY3RlZCA9IGZ1bmN0aW9uKCkge1xuXG4gICAgICAgICRzY29wZS5jdXJyUm93ID0gdGhpcy5yb3c7XG4gICAgICAgIC8vIGNvbnNvbGUubG9nKCdIRVJFJywgJHNjb3BlLmN1cnJSb3cpO1xuICAgIH1cblxuXG4gICAgLy8gY29uc29sZS5sb2coJHNjb3BlLnNpbmdsZVRhYmxlWzBdKVxuICAgIGZ1bmN0aW9uIENyZWF0ZUNvbHVtbnMoKSB7XG4gICAgICAgICRzY29wZS5jb2x1bW5zID0gW107XG4gICAgICAgIHZhciB0YWJsZSA9ICRzY29wZS5zaW5nbGVUYWJsZVswXVswXTtcblxuXG4gICAgICAgIGZvciAodmFyIHByb3AgaW4gdGFibGUpIHtcbiAgICAgICAgICAgIGlmIChwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLmNvbHVtbnMucHVzaChwcm9wKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cblxuICAgIENyZWF0ZUNvbHVtbnMoKTtcblxuICAgIC8vdGhpcyBmdW5jdGlvbiB3aWxsIHJlIHJ1biB3aGVuIHRoZSBmaWx0ZXIgZnVuY3Rpb24gaXMgaW52b2tlZCwgaW4gb3JkZXIgdG8gcmVwb3B1bGF0ZSB0aGUgdGFibGVcbiAgICBmdW5jdGlvbiBDcmVhdGVSb3dzKCkge1xuICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheSA9IFtdO1xuICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGVbMF0uZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIHZhciByb3dWYWx1ZXMgPSBbXTtcbiAgICAgICAgICAgIGZvciAodmFyIHByb3AgaW4gcm93KSB7XG4gICAgICAgICAgICAgICAgaWYgKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpIHJvd1ZhbHVlcy5wdXNoKHJvd1twcm9wXSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5LnB1c2gocm93VmFsdWVzKVxuICAgICAgICB9KVxuICAgIH1cblxuICAgIC8vIFNvcnQgdGhlIHZhbHVlcyBpbiBzaW5nbGVUYWJsZSBzbyB0aGF0IGFsbCB0aGUgdmFsdWVzIGZvciBhIGdpdmVuIHJvdyBhcmUgZ3JvdXBlZFxuICAgIENyZWF0ZVJvd3MoKTtcblxuXG4gICAgJHNjb3BlLnNldEZvcmVpZ25LZXkgPSBmdW5jdGlvbihkYk5hbWUsIHRibE5hbWUsIHJvd0lkLCBuZXdSb3cpIHtcbiAgICAgICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoKTtcbiAgICAgICAgY29uc29sZS5sb2coJ0hFUkUnLCAkc2NvcGUuY29sdW1uTmFtZSk7XG4gICAgICAgIGNvbnNvbGUubG9nKGRiTmFtZSwgdGJsTmFtZSwgcm93SWQsIG5ld1JvdywgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSlcbiAgICAgICAgVGFibGVGYWN0b3J5LnVwZGF0ZUpvaW5UYWJsZShkYk5hbWUsIHRibE5hbWUsIHJvd0lkLCBuZXdSb3csICRzdGF0ZVBhcmFtcy50YWJsZU5hbWUsICRzY29wZS5jb2x1bW5OYW1lKTtcbiAgICAgICAgICAgIC8vIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgLy8gICAgIC8vICRzdGF0ZS5nbygnVGFibGUuU2luZ2xlJywgeyBkYk5hbWU6ICRzY29wZS5kYk5hbWUsIHRhYmxlTmFtZTogJHNjb3BlLnNpbmdsZVRhYmxlIH0sIHsgcmVsb2FkOiB0cnVlIH0pXG4gICAgICAgICAgICAvLyB9KVxuICAgIH1cblxuXG5cbiAgICAkc2NvcGUub2sgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoJHNjb3BlLnNlbGVjdGVkLml0ZW0pO1xuICAgIH07XG5cbiAgICAkc2NvcGUuY2FuY2VsID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICR1aWJNb2RhbEluc3RhbmNlLmRpc21pc3MoJ2NhbmNlbCcpO1xuICAgIH07XG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnc2lnbnVwJywge1xuICAgICAgICB1cmw6ICcvc2lnbnVwJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9zaWdudXAvc2lnbnVwLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnU2lnbnVwQ3RybCdcbiAgICB9KTtcblxufSk7XG5cbmFwcC5jb250cm9sbGVyKCdTaWdudXBDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICAgJHNjb3BlLnNpZ251cCA9IHt9O1xuICAgICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgICAkc2NvcGUuc2VuZFNpZ251cCA9IGZ1bmN0aW9uIChzaWdudXBJbmZvKSB7XG4gICAgICAgICRzY29wZS5lcnJvciA9IG51bGw7XG4gICAgICAgIEF1dGhTZXJ2aWNlLnNpZ251cChzaWdudXBJbmZvKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbygnaG9tZScpO1xuICAgICAgICB9KS5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAkc2NvcGUuZXJyb3IgPSAnT29wcywgY2Fubm90IHNpZ24gdXAgd2l0aCB0aG9zZSBjcmVkZW50aWFscy4nO1xuICAgICAgICB9KTtcblxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ0Z1bGxzdGFja1BpY3MnLCBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIFtcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CN2dCWHVsQ0FBQVhRY0UuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vZmJjZG4tc3Bob3Rvcy1jLWEuYWthbWFpaGQubmV0L2hwaG90b3MtYWsteGFwMS90MzEuMC04LzEwODYyNDUxXzEwMjA1NjIyOTkwMzU5MjQxXzgwMjcxNjg4NDMzMTI4NDExMzdfby5qcGcnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0ItTEtVc2hJZ0FFeTlTSy5qcGcnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I3OS1YN29DTUFBa3c3eS5qcGcnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0ItVWo5Q09JSUFJRkFoMC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I2eUl5RmlDRUFBcWwxMi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFLVQ3NWxXQUFBbXFxSi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFdlpBZy1WQUFBazkzMi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFZ05NZU9YSUFJZkRoSy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFUXlJRE5XZ0FBdTYwQi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NDRjNUNVFXOEFFMmxHSi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NBZVZ3NVNXb0FBQUxzai5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NBYUpJUDdVa0FBbElHcy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NBUU93OWxXRUFBWTlGbC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0ItT1FiVnJDTUFBTndJTS5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I5Yl9lcndDWUFBd1JjSi5wbmc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I1UFRkdm5DY0FFQWw0eC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I0cXdDMGlDWUFBbFBHaC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0IyYjMzdlJJVUFBOW8xRC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0J3cEl3cjFJVUFBdk8yXy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0JzU3NlQU5DWUFFT2hMdy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NKNHZMZnVVd0FBZGE0TC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NJN3d6akVWRUFBT1BwUy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NJZEh2VDJVc0FBbm5IVi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NHQ2lQX1lXWUFBbzc1Vi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NJUzRKUElXSUFJMzdxdS5qcGc6bGFyZ2UnXG4gICAgXTtcbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ1JhbmRvbUdyZWV0aW5ncycsIGZ1bmN0aW9uICgpIHtcblxuICAgIHZhciBnZXRSYW5kb21Gcm9tQXJyYXkgPSBmdW5jdGlvbiAoYXJyKSB7XG4gICAgICAgIHJldHVybiBhcnJbTWF0aC5mbG9vcihNYXRoLnJhbmRvbSgpICogYXJyLmxlbmd0aCldO1xuICAgIH07XG5cbiAgICB2YXIgZ3JlZXRpbmdzID0gW1xuICAgICAgICAnSGVsbG8sIHdvcmxkIScsXG4gICAgICAgICdBdCBsb25nIGxhc3QsIEkgbGl2ZSEnLFxuICAgICAgICAnSGVsbG8sIHNpbXBsZSBodW1hbi4nLFxuICAgICAgICAnV2hhdCBhIGJlYXV0aWZ1bCBkYXkhJyxcbiAgICAgICAgJ0lcXCdtIGxpa2UgYW55IG90aGVyIHByb2plY3QsIGV4Y2VwdCB0aGF0IEkgYW0geW91cnMuIDopJyxcbiAgICAgICAgJ1RoaXMgZW1wdHkgc3RyaW5nIGlzIGZvciBMaW5kc2F5IExldmluZS4nLFxuICAgICAgICAn44GT44KT44Gr44Gh44Gv44CB44Om44O844K244O85qeY44CCJyxcbiAgICAgICAgJ1dlbGNvbWUuIFRvLiBXRUJTSVRFLicsXG4gICAgICAgICc6RCcsXG4gICAgICAgICdZZXMsIEkgdGhpbmsgd2VcXCd2ZSBtZXQgYmVmb3JlLicsXG4gICAgICAgICdHaW1tZSAzIG1pbnMuLi4gSSBqdXN0IGdyYWJiZWQgdGhpcyByZWFsbHkgZG9wZSBmcml0dGF0YScsXG4gICAgICAgICdJZiBDb29wZXIgY291bGQgb2ZmZXIgb25seSBvbmUgcGllY2Ugb2YgYWR2aWNlLCBpdCB3b3VsZCBiZSB0byBuZXZTUVVJUlJFTCEnLFxuICAgIF07XG5cbiAgICByZXR1cm4ge1xuICAgICAgICBncmVldGluZ3M6IGdyZWV0aW5ncyxcbiAgICAgICAgZ2V0UmFuZG9tR3JlZXRpbmc6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiBnZXRSYW5kb21Gcm9tQXJyYXkoZ3JlZXRpbmdzKTtcbiAgICAgICAgfVxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZSgnZnVsbHN0YWNrTG9nbycsIGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4ge1xuICAgICAgICByZXN0cmljdDogJ0UnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL2Z1bGxzdGFjay1sb2dvL2Z1bGxzdGFjay1sb2dvLmh0bWwnXG4gICAgfTtcbn0pOyIsImFwcC5kaXJlY3RpdmUoJ3NpZGViYXInLCBmdW5jdGlvbiAoJHJvb3RTY29wZSwgQXV0aFNlcnZpY2UsIEFVVEhfRVZFTlRTLCAkc3RhdGUpIHtcblxuICAgIHJldHVybiB7XG4gICAgICAgIHJlc3RyaWN0OiAnRScsXG4gICAgICAgIHNjb3BlOiB7fSxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9uYXZiYXIvbmF2YmFyLmh0bWwnLFxuICAgICAgICBsaW5rOiBmdW5jdGlvbiAoc2NvcGUpIHtcblxuICAgICAgICAgICAgc2NvcGUuaXRlbXMgPSBbXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ0hvbWUnLCBzdGF0ZTogJ2hvbWUnIH0sXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ0Fib3V0Jywgc3RhdGU6ICdhYm91dCcgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnRG9jdW1lbnRhdGlvbicsIHN0YXRlOiAnZG9jcycgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnTWVtYmVycyBPbmx5Jywgc3RhdGU6ICdtZW1iZXJzT25seScsIGF1dGg6IHRydWUgfVxuICAgICAgICAgICAgXTtcblxuICAgICAgICAgICAgc2NvcGUudXNlciA9IG51bGw7XG5cbiAgICAgICAgICAgIHNjb3BlLmlzTG9nZ2VkSW4gPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgc2NvcGUubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIEF1dGhTZXJ2aWNlLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnbGFuZGluZ1BhZ2UnKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHZhciBzZXRVc2VyID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpLnRoZW4oZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgICAgICAgICAgICAgc2NvcGUudXNlciA9IHVzZXI7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICB2YXIgcmVtb3ZlVXNlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBzY29wZS51c2VyID0gbnVsbDtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHNldFVzZXIoKTtcblxuICAgICAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMubG9naW5TdWNjZXNzLCBzZXRVc2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLmxvZ291dFN1Y2Nlc3MsIHJlbW92ZVVzZXIpO1xuICAgICAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsIHJlbW92ZVVzZXIpO1xuXG4gICAgICAgIH1cblxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZSgncmFuZG9HcmVldGluZycsIGZ1bmN0aW9uIChSYW5kb21HcmVldGluZ3MpIHtcblxuICAgIHJldHVybiB7XG4gICAgICAgIHJlc3RyaWN0OiAnRScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvY29tbW9uL2RpcmVjdGl2ZXMvcmFuZG8tZ3JlZXRpbmcvcmFuZG8tZ3JlZXRpbmcuaHRtbCcsXG4gICAgICAgIGxpbms6IGZ1bmN0aW9uIChzY29wZSkge1xuICAgICAgICAgICAgc2NvcGUuZ3JlZXRpbmcgPSBSYW5kb21HcmVldGluZ3MuZ2V0UmFuZG9tR3JlZXRpbmcoKTtcbiAgICAgICAgfVxuICAgIH07XG5cbn0pOyJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
