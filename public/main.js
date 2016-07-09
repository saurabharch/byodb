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

app.config(function ($stateProvider) {
    $stateProvider.state('landingPage', {
        url: '/',
        templateUrl: 'js/landingPage/landingPage.html'
    });
});
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
    $scope.singleTable = singleTable[0];
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcC5qcyIsImFib3V0L2Fib3V0LmpzIiwiZG9jcy9kb2NzLmpzIiwiY3JlYXRlZGIvY3JlYXRlREIuY29udHJvbGxlci5qcyIsImNyZWF0ZWRiL2NyZWF0ZURCLmZhY3RvcnkuanMiLCJjcmVhdGVkYi9jcmVhdGVEQi5zdGF0ZS5qcyIsImZzYS9mc2EtcHJlLWJ1aWx0LmpzIiwibGFuZGluZ1BhZ2UvbGFuZGluZ1BhZ2Uuc3RhdGUuanMiLCJob21lL2hvbWUuY29udHJvbGxlci5qcyIsImhvbWUvaG9tZS5mYWN0b3J5LmpzIiwiaG9tZS9ob21lLnN0YXRlLmpzIiwibWVtYmVycy1vbmx5L21lbWJlcnMtb25seS5qcyIsImxvZ2luL2xvZ2luLmpzIiwib2F1dGgvb2F1dGgtYnV0dG9uLmRpcmVjdGl2ZS5qcyIsInNpZ251cC9zaWdudXAuanMiLCJ0YWJsZS9hc3NvY2lhdGlvbi5jb250cm9sbGVyLmpzIiwidGFibGUvZGVsZXRlREJNb2RhbC5qcyIsInRhYmxlL2RlbGV0ZVRhYmxlTW9kYWwuanMiLCJ0YWJsZS9qb2luLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS9xdWVyeS5jb250cm9sbGVyLmpzIiwidGFibGUvc2luZ2xldGFibGUuY29udHJvbGxlci5qcyIsInRhYmxlL3RhYmxlLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS90YWJsZS5mYWN0b3J5LmpzIiwidGFibGUvdGFibGUuc3RhdGUuanMiLCJ0YWJsZS90aHJvdWdoLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS90aHJvdWdoTW9kYWwuY29udHJvbGxlci5qcyIsImNvbW1vbi9mYWN0b3JpZXMvRnVsbHN0YWNrUGljcy5qcyIsImNvbW1vbi9mYWN0b3JpZXMvUmFuZG9tR3JlZXRpbmdzLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvZnVsbHN0YWNrLWxvZ28vZnVsbHN0YWNrLWxvZ28uanMiLCJjb21tb24vZGlyZWN0aXZlcy9uYXZiYXIvbmF2YmFyLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvcmFuZG8tZ3JlZXRp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QSxTQUZBLEVBRUEsS0FGQSxDQUVBLFlBQUE7QUFDQSxtQkFBQSxLQUFBLEdBQUEsOENBQUE7QUFDQSxTQUpBO0FBTUEsS0FSQTtBQVVBLENBZkE7O0FDVkEsSUFBQSxVQUFBLENBQUEseUJBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxpQkFBQSxFQUFBLFdBQUEsRUFBQSxZQUFBLEVBQUEsV0FBQSxFQUFBLFlBQUEsRUFBQSxNQUFBLEVBQUEsUUFBQSxFQUFBLFlBQUEsRUFBQSxTQUFBLEVBQUEsT0FBQSxFQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxhQUFBLE1BQUE7O0FBRUEsV0FBQSxXQUFBLEdBQUEsUUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxZQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLFNBQUE7O0FBRUEsV0FBQSxPQUFBLEdBQUEsT0FBQTs7QUFFQSxXQUFBLEdBQUEsR0FBQSxHQUFBOztBQUVBLFdBQUEsV0FBQSxHQUFBLFlBQUE7O0FBRUEsZUFBQSxPQUFBLEdBQUEsS0FBQSxHQUFBO0FBQ0EsZ0JBQUEsR0FBQSxDQUFBLE9BQUEsT0FBQTtBQUNBLEtBSkE7O0FBUUEsYUFBQSxhQUFBLEdBQUE7QUFDQSxlQUFBLE9BQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxRQUFBLFNBQUEsQ0FBQSxDQUFBOztBQUdBLGFBQUEsSUFBQSxJQUFBLElBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxPQUFBLENBQUEsSUFBQSxDQUFBLElBQUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7OztBQUlBLGFBQUEsVUFBQSxHQUFBO0FBQ0EsZUFBQSxhQUFBLEdBQUEsRUFBQTtBQUNBLGlCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLFlBQUEsRUFBQTtBQUNBLGlCQUFBLElBQUEsSUFBQSxJQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBLFVBQUEsSUFB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QSxPQUFBLFNBQUEsQ0FBQSxDQUFBLENBQUE7O0FBR0EsYUFBQSxJQUFBLElBQUEsSUFBQSxLQUFBLEVBQUE7QUFDQSxnQkFBQSxTQUFBLFlBQUEsSUFBQSxTQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsSUFBQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTs7O0FBSUEsYUFBQSxVQUFBLEdBQUE7QUFDQSxZQUFBLEtBQUE7QUFDQSxlQUFBLGFBQUEsR0FBQSxFQUFBO0FBQ0Esa0JBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsWUFBQSxFQUFBO0FBQ0EsaUJBQUEsSUFBQSxJQUFBLElBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUEsVUFBQSxJQUFBLENBQUEsSUFBQSxJQUFBLENBQUE7QUFDQTtBQUNBLG1CQUFBLGFBQUEsQ0FBQSxJQUFBLENBQUEsU0FBQTtBQUNBLFNBTkE7QUFPQTs7O0FBR0E7QUFHQSxDQXJDQTtBQ0FBLElBQUEsVUFBQSxDQUFBLGdCQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQTs7QUFFQSxXQUFBLE9BQUEsR0FBQSxVQUFBLGVBQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLENBQUEsZUFBQSxFQUFBLE9BQUEsSUFBQSxDQUFBLEtBQ0E7QUFDQSxpQkFBQSxJQUFBLElBQUEsSUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxVQUFBLElBQUEsSUFBQSxFQUFBLFFBQUEsR0FBQSxXQUFBLEVBQUE7QUFDQSxvQkFBQSxZQUFBLGdCQUFBLFFBQUEsR0FBQSxXQUFBLEVBQUE7QUFDQSx3QkFBQSxHQUFBLENBQUEsT0FBQSxFQUFBLFNBQUEsRUFBQSxRQUFBLE9BQUEsQ0FBQSxTQUFBLE1BQUEsQ0FBQSxDQUFBO0FBQ0Esb0JBQUEsUUFBQSxPQUFBLENBQUEsU0FBQSxNQUFBLENBQUEsQ0FBQSxFQUFBLE9BQUEsSUFBQTtBQUNBO0FBQ0E7QUFDQSxlQUFBLEtBQUE7QUFDQSxLQVhBO0FBYUEsQ0FmQTtBQ0FBLElBQUEsVUFBQSxDQUFBLGlCQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQSxXQUFBLEVBQUEsT0FBQSxFQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsWUFBQSxFQUFBLElBQUEsRUFBQTs7OztBQUlBLFdBQUEsU0FBQSxHQUFBLGFBQUEsTUFBQTtBQUNBLFdBQUEsWUFBQSxHQUFBLGFBQUEsU0FBQTtBQUNBLFdBQUEsV0FBQSxHQUFBLFlBQUEsQ0FBQSxDQUFBO0FBQ0EsV0FBQSxXQUFBLEdBQUEsS0FBQTtBQUNBLFdBQUEsWUFBQSxHQUFBLFlBQUE7O0FBRUEsUUFBQSxPQUFBLFlBQUEsQ0FBQSxNQUFBLEdBQUEsQ0FBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLFlBQUEsQ0FBQSxDQUFBLEVBQUEsU0FBQSxNQUFBLGFBQUEsU0FBQSxFQUFBO0FBQ0EsbUJBQUEsRUFBQSxDQUFBLGVBQUEsRUFBQSxFQUFBLFFBQUEsYUFBQSxNQUFBLEVBQUEsV0FBQSxhQUFBLFNBQUEsRUFBQTtBQUNBO0FBQ0E7O0FBRUEsYUFBQSxnQkFBQSxHQUFBO0FBQ0EsWUFBQSxjQUFBLEVBQUE7QUFDQSxlQUFBLFlBQUEsQ0FBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxJQUFBLE1BQUEsS0FBQSxPQUFBLFlBQUEsSUFBQSxJQUFBLGFBQUEsS0FBQSxRQUFBLEVBQUE7QUFDQSw0QkFBQSxJQUFBLE1BQUEsSUFBQSxJQUFBLE1BQUE7QUFDQSxhQUZBLE1BRUEsSUFBQSxJQUFBLE1BQUEsS0FBQSxPQUFBLFlBQUEsSUFBQSxJQUFBLGFBQUEsS0FBQSxRQUFBLEVBQUE7QUFDQSw0QkFBQSxJQUFBLE1BQUEsSUFBQSxJQUFBLE1BQUE7QUFDQTtBQUNBLFNBTkE7QUFPQSxlQUFBLFdBQUEsR0FBQSxXQUFBO0FBQ0E7O0FBRUE7O0FBR0EsV0FBQSxZQUFBLEdBQUEsWUFBQTs7QUFFQSxXQUFBLE9BQUEsR0FBQSxDQUFBOztBQUVBLFdBQUEsR0FBQSxHQUFBLE9BQUEsV0FBQSxDQUFBLEdBQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGVBQUEsSUFBQSxFQUFBO0FBQ0EsS0FGQSxDQUFBOzs7QUFLQSxXQUFBLFVBQUEsR0FBQSxLQUFBO0FBQ0EsV0FBQSxZQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsVUFBQSxHQUFBLENBQUEsT0FBQSxVQUFBO0FBQ0EsS0FGQTs7QUFJQSxXQUFBLGNBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsYUFBQSxFQUFBO0FBQ0Esc0JBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxRQUFBLEVBQUE7QUFDQSw2QkFBQSxTQUFBLENBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxJQUFBLFFBQUEsRUFBQSxDQUFBLEVBQUEsT0FBQSxDQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsMkJBQUEsV0FBQSxHQUFBLE1BQUE7QUFDQTtBQUNBLGlCQUpBO0FBS0E7QUFDQSxTQVJBO0FBU0EsZUFBQSxVQUFBLEdBQUEsS0FBQTtBQUNBLEtBWEE7O0FBYUEsV0FBQSxTQUFBLEdBQUEsVUFBQSxhQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsV0FBQSxFQUFBO0FBQ0EsMEJBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsUUFBQSxHQUFBLElBQUE7QUFDQSxhQUZBO0FBR0EsU0FKQSxNQUlBO0FBQ0EsMEJBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsUUFBQSxHQUFBLEtBQUE7QUFDQSxhQUZBO0FBR0E7QUFDQSxLQVZBOztBQVlBLFdBQUEsZ0JBQUEsR0FBQSxVQUFBLGFBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxXQUFBLEtBQUEsSUFBQSxFQUFBO0FBQ0EsbUJBQUEsV0FBQSxHQUFBLEtBQUE7QUFDQTtBQUNBLEtBSkE7O0FBTUEsV0FBQSxTQUFBLEdBQUEsVUFBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLHFCQUFBLFNBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLEdBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSxtQkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsU0FKQTtBQUtBLEtBTkE7O0FBUUEsV0FBQSxZQUFBLEdBQUEsVUFBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLFVBQUEsRUFBQTtBQUNBLHFCQUFBLFlBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLFVBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSxtQkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0E7QUFDQSxTQUxBO0FBTUEsS0FQQTs7QUFTQSxXQUFBLE1BQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxTQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsQ0FBQSxVQUFBLE9BQUEsRUFBQTtBQUNBLG1CQUFBLElBQUEsQ0FBQSxRQUFBLE1BQUEsQ0FBQSxDQUFBLEVBQUEsS0FBQTtBQUNBLFNBRkE7QUFHQSxZQUFBLFNBQUEsT0FBQSxJQUFBLENBQUEsVUFBQSxDQUFBLEVBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBO0FBQ0EsU0FGQSxDQUFBO0FBR0EsWUFBQSxPQUFBLE1BQUEsR0FBQSxDQUFBLEVBQUE7QUFDQSx5QkFBQSxNQUFBLENBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxPQUFBLENBQUEsSUFBQSxDQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsdUJBQUEsV0FBQSxHQUFBLE1BQUE7QUFDQTtBQUNBLGFBSkE7QUFNQSxTQVBBLE1BT0E7QUFDQSx5QkFBQSxNQUFBLENBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxDQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsdUJBQUEsV0FBQSxHQUFBLE1BQUE7QUFDQTtBQUNBLGFBSkE7QUFLQTtBQUNBLEtBdEJBOztBQXdCQSxXQUFBLFNBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUE7QUFDQSxZQUFBLFVBQUEsT0FBQSxPQUFBLENBQUEsSUFBQSxDQUFBLEdBQUEsRUFBQSxLQUFBLENBQUEsTUFBQSxDQUFBO0FBQ0EsWUFBQSxPQUFBLEVBQUE7QUFDQSxnQkFBQSxhQUFBLFFBQUEsSUFBQSxDQUFBLFVBQUEsQ0FBQSxFQUFBLENBQUEsRUFBQTtBQUNBLHVCQUFBLElBQUEsQ0FBQTtBQUNBLGFBRkEsQ0FBQTtBQUdBLGdCQUFBLFdBQUEsT0FBQSxXQUFBLENBQUEsQ0FBQSxJQUFBLENBQUE7QUFDQSxnQkFBQSxhQUFBLFlBQUEsU0FBQSxRQUFBLEVBQUE7O0FBRUEseUJBQUEsU0FBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUNBLElBREEsQ0FDQSxZQUFBO0FBQ0EsdUJBQUEsYUFBQSxjQUFBLENBQUEsYUFBQSxNQUFBLEVBQUEsYUFBQSxTQUFBLENBQUE7QUFDQSxhQUhBLEVBSUEsSUFKQSxDQUlBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsdUJBQUEsV0FBQSxHQUFBLFNBQUEsQ0FBQSxDQUFBO0FBQ0E7QUFDQTtBQUNBLGFBUkE7QUFTQSxTQWhCQSxNQWdCQTtBQUNBLGdCQUFBLGFBQUEsT0FBQSxPQUFBLENBQUEsTUFBQSxHQUFBLENBQUE7QUFDQSxnQkFBQSxhQUFBLFlBQUEsVUFBQTtBQUNBLHlCQUFBLFNBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLFVBQUEsRUFDQSxJQURBLENBQ0EsWUFBQTtBQUNBLHVCQUFBLGFBQUEsY0FBQSxDQUFBLGFBQUEsTUFBQSxFQUFBLGFBQUEsU0FBQSxDQUFBO0FBQ0EsYUFIQSxFQUlBLElBSkEsQ0FJQSxVQUFBLFFBQUEsRUFBQTtBQUNBLHVCQUFBLFdBQUEsR0FBQSxTQUFBLENBQUEsQ0FBQTtBQUNBO0FBQ0E7QUFDQSxhQVJBO0FBU0E7QUFFQSxLQWhDQTs7Ozs7O0FBc0NBLGFBQUEsYUFBQSxHQUFBO0FBQ0EsZUFBQSxPQUFBLEdBQUEsRUFBQTtBQUNBLGVBQUEsZUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLFFBQUEsT0FBQSxXQUFBLENBQUEsQ0FBQSxDQUFBOztBQUdBLGFBQUEsSUFBQSxJQUFBLElBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxPQUFBLENBQUEsSUFBQSxDQUFBLElBQUE7QUFDQSx1QkFBQSxlQUFBLENBQUEsSUFBQSxDQUFBLElBQUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7O0FBRUEsYUFBQSxvQkFBQSxHQUFBO0FBQ0EsWUFBQSxPQUFBLFlBQUEsQ0FBQSxNQUFBLEdBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsY0FBQSxHQUFBLEVBQUE7QUFDQSxtQkFBQSxZQUFBLENBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsSUFBQSxNQUFBLEtBQUEsT0FBQSxZQUFBLElBQUEsSUFBQSxhQUFBLEtBQUEsU0FBQSxFQUFBO0FBQ0Esd0JBQUEsVUFBQSxFQUFBO0FBQ0EsNEJBQUEsSUFBQSxHQUFBLElBQUEsTUFBQTtBQUNBLHdCQUFBLElBQUEsT0FBQSxFQUFBO0FBQ0EsZ0NBQUEsS0FBQSxHQUFBLElBQUEsT0FBQTtBQUNBLGdDQUFBLFNBQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSxxQkFIQSxNQUdBO0FBQ0EsZ0NBQUEsS0FBQSxHQUFBLElBQUEsTUFBQTtBQUNBLGdDQUFBLFNBQUEsR0FBQSxJQUFBLE1BQUE7QUFDQTtBQUNBLDJCQUFBLGNBQUEsQ0FBQSxJQUFBLENBQUEsT0FBQTtBQUNBLGlCQVhBLE1BV0EsSUFBQSxJQUFBLE1BQUEsS0FBQSxPQUFBLFlBQUEsSUFBQSxJQUFBLGFBQUEsS0FBQSxTQUFBLEVBQUE7QUFDQSx3QkFBQSxVQUFBLEVBQUE7QUFDQSw0QkFBQSxJQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0Esd0JBQUEsSUFBQSxPQUFBLEVBQUE7QUFDQSxnQ0FBQSxLQUFBLEdBQUEsSUFBQSxPQUFBO0FBQ0EsZ0NBQUEsU0FBQSxHQUFBLElBQUEsTUFBQTtBQUNBLHFCQUhBLE1BR0E7QUFDQSxnQ0FBQSxLQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EsZ0NBQUEsU0FBQSxHQUFBLElBQUEsTUFBQTtBQUNBO0FBQ0EsMkJBQUEsY0FBQSxDQUFBLElBQUEsQ0FBQSxPQUFBO0FBQ0E7QUFDQSxhQXhCQTtBQXlCQTtBQUNBOztBQUVBOzs7QUFHQSxhQUFBLFVBQUEsR0FBQTtBQUNBLGVBQUEsYUFBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLFdBQUEsQ0FBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxZQUFBLEVBQUE7QUFDQSxnQkFBQSxTQUFBLEVBQUE7O0FBRUEsaUJBQUEsSUFBQSxJQUFBLElBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUEsVUFBQSxJQUFBLENBQUE7QUFDQSx5QkFBQSxJQURBO0FBRUEsMkJBQUEsSUFBQSxJQUFBO0FBRkEsaUJBQUE7QUFJQTtBQUNBLG1CQUFBLE1BQUEsR0FBQSxTQUFBO0FBQ0EsbUJBQUEsYUFBQSxDQUFBLElBQUEsQ0FBQSxNQUFBO0FBQ0EsU0FaQTtBQWFBOzs7QUFHQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsSUFBQSxFQUFBO0FBQ0EscUJBQUEsTUFBQSxDQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsSUFBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE1BQUEsRUFBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxPQUFBLElBQUE7QUFDQTtBQUNBLFNBSkE7QUFLQSxLQU5BOztBQVNBLFdBQUEsWUFBQSxHQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZUFBQSxPQUFBLFdBQUEsQ0FBQSxjQUFBLENBQUEsR0FBQSxDQUFBO0FBQ0EsS0FGQTs7QUFJQSxXQUFBLFdBQUEsR0FBQSxhQUFBLFdBQUE7Ozs7Ozs7O0FBU0EsV0FBQSxlQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLGFBQUEsR0FBQSxVQUFBLEdBQUEsRUFBQSxVQUFBLEVBQUEsQ0FBQSxFQUFBO0FBQ0EsZUFBQSxPQUFBLENBQUEsQ0FBQSxJQUFBLFVBQUE7O0FBRUEsWUFBQSxTQUFBLEVBQUEsUUFBQSxPQUFBLGVBQUEsQ0FBQSxDQUFBLENBQUEsRUFBQSxRQUFBLFVBQUEsRUFBQTs7O0FBR0EsWUFBQSxPQUFBLGVBQUEsQ0FBQSxNQUFBLEtBQUEsQ0FBQSxFQUFBO0FBQUEsbUJBQUEsZUFBQSxDQUFBLElBQUEsQ0FBQSxNQUFBO0FBQUEsU0FBQSxNQUFBO0FBQ0EsaUJBQUEsSUFBQSxJQUFBLENBQUEsRUFBQSxJQUFBLE9BQUEsZUFBQSxDQUFBLE1BQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxPQUFBLGVBQUEsQ0FBQSxDQUFBLEVBQUEsTUFBQSxLQUFBLE9BQUEsTUFBQSxFQUFBO0FBQ0EsMkJBQUEsZUFBQSxDQUFBLENBQUEsSUFBQSxNQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsbUJBQUEsZUFBQSxDQUFBLElBQUEsQ0FBQSxNQUFBO0FBQ0E7O0FBRUEsS0FoQkE7Ozs7QUFvQkEsV0FBQSxlQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxVQUFBLEdBQUEsRUFBQSxPQUFBLEVBQUEsR0FBQSxFQUFBLENBQUEsRUFBQSxDQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsT0FBQSxlQUFBO0FBQ0EsWUFBQSxRQUFBLEtBQUE7QUFDQSxZQUFBLFVBQUEsS0FBQSxDQUFBLENBQUE7QUFDQSxhQUFBLElBQUEsSUFBQSxDQUFBLEVBQUEsSUFBQSxPQUFBLGVBQUEsQ0FBQSxNQUFBLEVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsTUFBQSxPQUFBLGVBQUEsQ0FBQSxDQUFBLENBQUE7QUFDQSxvQkFBQSxHQUFBLENBQUEsR0FBQTtBQUNBLGdCQUFBLElBQUEsSUFBQSxNQUFBLENBQUEsRUFBQTtBQUNBLHdCQUFBLElBQUE7QUFDQSxvQkFBQSxJQUFBLE9BQUEsQ0FBQSxFQUFBLElBQUEsT0FBQSxJQUFBLE9BQUE7QUFDQSxvQkFBQSxPQUFBLElBQUEsT0FBQTtBQUNBO0FBQ0E7QUFDQSxZQUFBLENBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JBQUEsU0FBQSxFQUFBO0FBQ0EsbUJBQUEsSUFBQSxJQUFBLENBQUE7QUFDQSxtQkFBQSxPQUFBLElBQUEsT0FBQTtBQUNBLG1CQUFBLGVBQUEsQ0FBQSxJQUFBLENBQUEsTUFBQTtBQUNBO0FBQ0EsS0FuQkE7O0FBcUJBLFdBQUEsYUFBQSxHQUFBLFlBQUE7QUFDQSxZQUFBLE9BQUEsRUFBQSxNQUFBLE9BQUEsZUFBQSxFQUFBLFNBQUEsT0FBQSxlQUFBLEVBQUE7QUFDQSxxQkFBQSxhQUFBLENBQUEsT0FBQSxTQUFBLEVBQUEsT0FBQSxZQUFBLEVBQUEsSUFBQTtBQUNBLEtBSEE7O0FBTUEsV0FBQSxXQUFBLEdBQUEsWUFBQTtBQUNBLHFCQUFBLFdBQUEsQ0FBQSxPQUFBLFlBQUEsRUFDQSxJQURBLENBQ0EsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxPQUFBLEVBQUEsRUFBQSxRQUFBLE9BQUEsU0FBQSxFQUFBLEVBQUEsRUFBQSxRQUFBLElBQUEsRUFBQTtBQUNBLFNBSEE7QUFJQSxLQUxBOzs7O0FBU0EsV0FBQSx3QkFBQSxHQUFBLEVBQUE7O0FBRUEsV0FBQSxhQUFBLEdBQUEsRUFBQTs7QUFFQSxpQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLElBQUEsTUFBQSxLQUFBLE9BQUEsWUFBQSxJQUFBLE9BQUEsd0JBQUEsQ0FBQSxPQUFBLENBQUEsSUFBQSxNQUFBLEtBQUEsQ0FBQSxDQUFBLEVBQUE7QUFDQSxtQkFBQSx3QkFBQSxDQUFBLElBQUEsQ0FBQSxJQUFBLE1BQUE7QUFDQSxTQUZBLE1BRUEsSUFBQSxJQUFBLE1BQUEsS0FBQSxPQUFBLFlBQUEsSUFBQSxPQUFBLHdCQUFBLENBQUEsT0FBQSxDQUFBLElBQUEsTUFBQSxLQUFBLENBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsd0JBQUEsQ0FBQSxJQUFBLENBQUEsSUFBQSxNQUFBO0FBQ0E7QUFDQSxLQU5BOztBQVFBLFdBQUEsYUFBQSxHQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLGFBQUEsQ0FBQSxPQUFBLENBQUEsT0FBQSx3QkFBQSxDQUFBLEdBQUEsQ0FBQSxNQUFBLENBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsYUFBQSxDQUFBLElBQUEsQ0FBQSxPQUFBLHdCQUFBLENBQUEsR0FBQSxDQUFBO0FBQ0EsU0FGQSxNQUVBO0FBQ0EsZ0JBQUEsSUFBQSxPQUFBLGFBQUEsQ0FBQSxPQUFBLENBQUEsT0FBQSx3QkFBQSxDQUFBLEdBQUEsQ0FBQSxDQUFBO0FBQ0EsbUJBQUEsYUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBLEVBQUEsQ0FBQTtBQUNBO0FBQ0EsS0FQQTs7QUFTQSxXQUFBLGVBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsa0JBQUEsR0FBQSxZQUFBO0FBQ0EsWUFBQSxxQkFBQSxFQUFBO0FBQ0EsZUFBQSxhQUFBLENBQUEsT0FBQSxDQUFBLFVBQUEsU0FBQSxFQUFBO0FBQ0EsbUJBQUEsbUJBQUEsSUFBQSxDQUFBLGFBQUEsa0JBQUEsQ0FBQSxPQUFBLFNBQUEsRUFBQSxTQUFBLENBQUEsQ0FBQTtBQUNBLFNBRkE7QUFHQSxnQkFBQSxHQUFBLENBQUEsa0JBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxPQUFBLEVBQUE7QUFDQSxvQkFBQSxPQUFBLENBQUEsVUFBQSxNQUFBLEVBQUE7QUFDQSx1QkFBQSxlQUFBLENBQUEsSUFBQSxDQUFBLE1BQUE7QUFDQSx1QkFBQSxVQUFBO0FBQ0EsYUFIQTtBQUlBLFNBTkE7QUFRQSxLQWJBOztBQWVBLFFBQUEsa0JBQUEsRUFBQTtBQUNBLFFBQUEsVUFBQTs7QUFFQSxXQUFBLGtCQUFBLEdBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLENBQUEsZUFBQSxFQUFBLGtCQUFBLEVBQUE7O0FBRUEsWUFBQSxhQUFBLE9BQUEsZUFBQSxDQUFBLENBQUEsRUFBQSxTQUFBLEVBQUEsSUFBQSxDQUFBLENBQUE7QUFDQSxZQUFBLFlBQUEsSUFBQSxTQUFBO0FBQ0EscUJBQUEsU0FBQTs7QUFFQSxZQUFBLENBQUEsZ0JBQUEsU0FBQSxDQUFBLEVBQUEsZ0JBQUEsU0FBQSxJQUFBLEVBQUE7QUFDQSxZQUFBLGdCQUFBLFNBQUEsRUFBQSxPQUFBLENBQUEsVUFBQSxNQUFBLENBQUEsQ0FBQSxFQUFBO0FBQ0EsNEJBQUEsU0FBQSxFQUFBLE1BQUEsQ0FBQSxnQkFBQSxTQUFBLEVBQUEsT0FBQSxDQUFBLFVBQUEsQ0FBQSxFQUFBLENBQUE7QUFDQSxTQUZBLE1BRUE7QUFDQSw0QkFBQSxTQUFBLEVBQUEsSUFBQSxDQUFBLFVBQUE7QUFDQTtBQUNBLGVBQUEsZUFBQSxHQUFBLGVBQUE7QUFDQSxLQWRBOzs7QUFrQkEsV0FBQSxhQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLFdBQUE7O0FBRUEsV0FBQSxHQUFBLEdBQUEsRUFBQTs7OztBQUtBLFdBQUEsT0FBQSxHQUFBLFlBQUE7O0FBRUEsWUFBQSxrQkFBQSxPQUFBLE9BQUEsQ0FBQSxHQUFBLENBQUEsVUFBQSxPQUFBLEVBQUE7QUFDQSxtQkFBQSxPQUFBLFlBQUEsR0FBQSxHQUFBLEdBQUEsT0FBQTtBQUNBLFNBRkEsQ0FBQTtBQUdBLGFBQUEsSUFBQSxJQUFBLElBQUEsT0FBQSxlQUFBLEVBQUE7QUFDQSxtQkFBQSxlQUFBLENBQUEsSUFBQSxFQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdDQUFBLElBQUEsQ0FBQSxPQUFBLEdBQUEsR0FBQSxHQUFBO0FBQ0EsYUFGQTtBQUdBO0FBQ0EscUJBQUEsT0FBQSxDQUFBLE9BQUEsU0FBQSxFQUFBLE9BQUEsWUFBQSxFQUFBLE9BQUEsYUFBQSxFQUFBLE9BQUEsZUFBQSxFQUFBLE9BQUEsWUFBQSxFQUFBLGVBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxXQUFBLEVBQUE7QUFDQSxvQkFBQSxHQUFBLENBQUEsY0FBQSxFQUFBLFdBQUE7QUFDQSxtQkFBQSxXQUFBLEdBQUEsV0FBQTtBQUNBLFNBSkEsRUFLQSxJQUxBLENBS0EsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxvQkFBQTtBQUNBLFNBUEE7QUFRQSxLQWxCQTs7QUFvQkEsV0FBQSxpQkFBQSxHQUFBLElBQUE7O0FBRUEsV0FBQSxJQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsT0FBQSxFQUFBLEdBQUEsRUFBQSxLQUFBLEVBQUE7O0FBRUEsWUFBQSxnQkFBQSxVQUFBLElBQUEsQ0FBQTtBQUNBLHVCQUFBLE9BQUEsaUJBREE7QUFFQSx5QkFBQSxpQ0FGQTtBQUdBLHdCQUFBLHlCQUhBO0FBSUEscUJBQUE7QUFDQSw2QkFBQSx1QkFBQTtBQUNBLDJCQUFBLE9BQUEsV0FBQTtBQUNBLGlCQUhBO0FBSUEsMEJBQUEsa0JBQUEsWUFBQSxFQUFBO0FBQ0EsNEJBQUEsR0FBQSxDQUFBLE9BQUE7QUFDQSwyQkFBQSxhQUFBLFdBQUEsQ0FBQSxNQUFBLEVBQUEsT0FBQSxDQUFBO0FBQ0EsaUJBUEE7QUFRQSw4QkFBQSx3QkFBQTtBQUNBLDJCQUFBLE9BQUE7QUFDQSxpQkFWQTtBQVdBLDJCQUFBLHFCQUFBO0FBQ0EsMkJBQUEsT0FBQSxZQUFBO0FBQ0EsaUJBYkE7QUFjQSx5QkFBQSxtQkFBQTtBQUNBLDJCQUFBLEdBQUE7QUFDQSxpQkFoQkE7QUFpQkEscUJBQUEsZUFBQTtBQUNBLDJCQUFBLEtBQUE7QUFDQTtBQW5CQTtBQUpBLFNBQUEsQ0FBQTs7QUEyQkEsc0JBQUEsTUFBQSxDQUFBLElBQUEsQ0FBQSxZQUFBO0FBQ0Esb0JBQUEsR0FBQSxDQUFBLFFBQUE7QUFDQSxtQkFBQSxVQUFBO0FBQ0EsU0FIQTtBQUlBLEtBakNBOztBQW1DQSxXQUFBLGVBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxpQkFBQSxHQUFBLENBQUEsT0FBQSxpQkFBQTtBQUNBLEtBRkE7QUFJQSxDQXBiQTs7QUNBQSxJQUFBLFVBQUEsQ0FBQSxXQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLE1BQUEsRUFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBLFNBQUEsRUFBQSxXQUFBLEVBQUEsWUFBQSxFQUFBLFVBQUEsRUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxTQUFBOztBQUVBLFdBQUEsV0FBQSxHQUFBLEVBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBOztBQUVBLFdBQUEsWUFBQSxHQUFBLFlBQUE7O0FBRUEsV0FBQSxVQUFBLEdBQUEsVUFBQTs7QUFFQSxXQUFBLGdCQUFBLEdBQUEsYUFBQSxNQUFBLEdBQUEsUUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxPQUFBLFNBQUEsQ0FBQSxJQUFBLENBQUEsTUFBQTs7QUFFQSxXQUFBLEdBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxXQUFBLENBQUEsSUFBQSxDQUFBLEdBQUE7QUFDQSxLQUZBOztBQUlBLFdBQUEsTUFBQSxHQUFBLE1BQUEsQzs7QUFFQSxXQUFBLGdCQUFBLEdBQUEsQ0FBQSxRQUFBLEVBQUEsU0FBQSxDQUFBOztBQUVBLFdBQUEsTUFBQSxHQUFBLGFBQUEsTUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxLQUFBOztBQUVBLFdBQUEsZ0JBQUEsR0FBQSxVQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLFNBQUEsR0FBQSxJQUFBO0FBQ0EscUJBQUEsZ0JBQUEsQ0FBQSxXQUFBLEVBQUEsTUFBQTtBQUNBLEtBSEE7O0FBS0EsV0FBQSxZQUFBLEdBQUEsVUFBQSxTQUFBLEVBQUE7QUFDQSxZQUFBLGNBQUEsZUFBQSxJQUFBLGNBQUEsbUJBQUEsRUFBQSxPQUFBLElBQUE7QUFDQSxLQUZBOztBQUlBLFdBQUEsV0FBQSxHQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0EscUJBQUEsV0FBQSxDQUFBLEtBQUEsRUFDQSxJQURBLENBQ0EsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxPQUFBLEVBQUEsRUFBQSxRQUFBLE9BQUEsTUFBQSxFQUFBLEVBQUEsRUFBQSxRQUFBLElBQUEsRUFBQTtBQUNBLFNBSEE7QUFJQSxLQUxBOztBQU9BLFdBQUEsY0FBQSxHQUFBLFlBQUE7QUFDQSxlQUFBLFVBQUEsQ0FBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxJQUFBLFVBQUEsS0FBQSxPQUFBLEtBQUEsQ0FBQSxNQUFBLElBQUEsSUFBQSxXQUFBLEtBQUEsT0FBQSxLQUFBLENBQUEsTUFBQSxFQUFBLE9BQUEsSUFBQSxHQUFBLElBQUEsU0FBQTtBQUNBLFNBRkE7QUFHQSxLQUpBOztBQU1BLFdBQUEsYUFBQSxHQUFBLEVBQUE7O0FBRUEsV0FBQSxXQUFBLEdBQUEsYUFBQSxXQUFBO0FBRUEsQ0F0REE7O0FDQUEsSUFBQSxPQUFBLENBQUEsY0FBQSxFQUFBLFVBQUEsS0FBQSxFQUFBLFlBQUEsRUFBQTs7QUFFQSxRQUFBLGVBQUEsRUFBQTs7QUFFQSxhQUFBLFNBQUEsQ0FBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLElBQUEsSUFBQTtBQUNBOztBQUVBLGlCQUFBLFlBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUJBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGNBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFNBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUJBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLE1BQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsSUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsR0FBQSxTQUFBLEVBQUEsSUFBQSxDQUFBO0FBQ0EsS0FGQTs7QUFJQSxpQkFBQSxhQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLElBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsa0JBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQUEsSUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLE1BQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLElBQUEsQ0FBQSx5QkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsRUFBQSxFQUFBLFdBQUEsU0FBQSxFQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsU0FBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsTUFBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxHQUFBLEdBQUEsR0FBQSxLQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsWUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxVQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsTUFBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxHQUFBLFVBQUEsR0FBQSxVQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsU0FBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxDQUFBLDRCQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLENBQUE7QUFDQSxLQUZBO0FBR0EsaUJBQUEsV0FBQSxHQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0EsY0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBO0FBQ0EsZUFBQSxNQUFBLElBQUEsQ0FBQSxlQUFBLEVBQUEsS0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUpBOztBQU1BLGlCQUFBLFdBQUEsR0FBQSxVQUFBLFlBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsYUFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLGFBQUEsU0FBQSxDQUFBO0FBQ0EsS0FGQTs7QUFJQSxpQkFBQSxnQkFBQSxHQUFBLFVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxJQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLGNBQUEsRUFBQSxXQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsUUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLE1BQUEsQ0FBQSxtQkFBQSxNQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsZUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsb0NBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsa0JBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUNBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsaUNBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGtCQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQ0FBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxPQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBLGFBQUEsRUFBQSxlQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxFQUFBO0FBQ0EsYUFBQSxNQUFBLEdBQUEsTUFBQTtBQUNBLGFBQUEsTUFBQSxHQUFBLGNBQUEsQ0FBQSxDQUFBO0FBQ0EsYUFBQSxhQUFBLEdBQUEsYUFBQTtBQUNBLGFBQUEsZUFBQSxHQUFBLGVBQUE7QUFDQSxhQUFBLFlBQUEsR0FBQSxZQUFBOzs7O0FBSUEscUJBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxNQUFBLEtBQUEsTUFBQSxJQUFBLElBQUEsTUFBQSxLQUFBLEtBQUEsTUFBQSxFQUFBO0FBQ0EscUJBQUEsS0FBQSxHQUFBLElBQUEsTUFBQTtBQUNBLG9CQUFBLElBQUEsYUFBQSxLQUFBLFFBQUEsRUFBQTtBQUNBLHlCQUFBLE1BQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EsaUJBSEEsTUFJQTtBQUNBLHlCQUFBLE1BQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0E7QUFDQSxhQVZBLE1BV0EsSUFBQSxJQUFBLE1BQUEsS0FBQSxLQUFBLE1BQUEsSUFBQSxJQUFBLE1BQUEsS0FBQSxNQUFBLEVBQUE7QUFDQSxxQkFBQSxLQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0Esb0JBQUEsSUFBQSxhQUFBLEtBQUEsU0FBQSxFQUFBO0FBQ0EseUJBQUEsTUFBQSxHQUFBLElBQUEsTUFBQTtBQUNBLHlCQUFBLE1BQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSxpQkFIQSxNQUlBO0FBQ0EseUJBQUEsTUFBQSxHQUFBLElBQUEsTUFBQTtBQUNBLHlCQUFBLE1BQUEsR0FBQSxJQUFBLE1BQUE7QUFDQTtBQUNBO0FBQ0EsU0F2QkE7O0FBeUJBLGdCQUFBLEdBQUEsQ0FBQSxNQUFBLEVBQUEsSUFBQTs7QUFFQSxlQUFBLE1BQUEsR0FBQSxDQUFBLHVCQUFBLEVBQUEsSUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQXZDQTs7QUF5Q0EsaUJBQUEsY0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsR0FBQSxHQUFBLEdBQUEsRUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsV0FBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLE9BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsMkJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxPQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsYUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLE9BQUEsRUFBQSxPQUFBLEVBQUEsR0FBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxFQUFBO0FBQ0EsYUFBQSxNQUFBLEdBQUEsTUFBQTtBQUNBLGFBQUEsT0FBQSxHQUFBLE9BQUE7QUFDQSxhQUFBLE9BQUEsR0FBQSxPQUFBO0FBQ0EsYUFBQSxHQUFBLEdBQUEsR0FBQTtBQUNBLGFBQUEsR0FBQSxHQUFBLEdBQUE7O0FBRUEsZUFBQSxNQUFBLEdBQUEsQ0FBQSw2QkFBQSxFQUFBLElBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FWQTs7QUFZQSxpQkFBQSxlQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLEVBQUEsRUFBQSxNQUFBLEVBQUEsYUFBQSxFQUFBLFVBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxFQUFBO0FBQ0EsYUFBQSxNQUFBLEdBQUEsTUFBQTtBQUNBLGFBQUEsT0FBQSxHQUFBLFNBQUE7QUFDQSxhQUFBLEtBQUEsR0FBQSxFQUFBO0FBQ0EsYUFBQSxNQUFBLEdBQUEsTUFBQTtBQUNBLGFBQUEsYUFBQSxHQUFB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QSxXQUFBLFlBQUEsR0FBQSxZQUFBO0FBQ0EsV0FBQSxTQUFBLEdBQUEsRUFBQTtBQUNBLFdBQUEsV0FBQSxHQUFBLFlBQUEsQ0FBQSxDQUFBO0FBQ0EsV0FBQSxTQUFBLEdBQUEsYUFBQSxNQUFBO0FBQ0EsV0FBQSxTQUFBLEdBQUEsYUFBQSxTQUFBOztBQUVBLGFBQUEsVUFBQSxHQUFBO0FBQ0EsZUFBQSxZQUFBLENBQUEsT0FBQSxDQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JBQUEsTUFBQSxTQUFBLE1BQUEsYUFBQSxTQUFBLEVBQUE7QUFDQSx1QkFBQSxTQUFBLENBQUEsSUFBQSxDQUFBLE1BQUEsUUFBQSxDQUFBO0FBQ0EsdUJBQUEsU0FBQSxDQUFBLElBQUEsQ0FBQSxNQUFBLFFBQUEsQ0FBQSxFO0FBQ0E7QUFDQSxTQUxBO0FBTUE7O0FBRUE7O0FBRUEsYUFBQSxhQUFBLEdBQUE7QUFDQSxlQUFBLE9BQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxRQUFBLFlBQUEsQ0FBQSxFQUFBLENBQUEsQ0FBQTtBQUNBLGFBQUEsSUFBQSxJQUFBLElBQUEsS0FBQSxFQUFBO0FBQ0EsbUJBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxJQUFBO0FBQ0E7QUFDQTs7QUFFQTs7O0FBSUEsYUFBQSxVQUFBLEdBQUE7O0FBRUEsZUFBQSxhQUFBLEdBQUEsRUFBQTtBQUNBLGVBQUEsV0FBQSxDQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLFlBQUEsRUFBQTtBQUNBLGlCQUFBLElBQUEsSUFBQSxJQUFBLEdBQUEsRUFBQTtBQUNBLDBCQUFBLElBQUEsQ0FBQSxJQUFBLElBQUEsQ0FBQTtBQUNBO0FBQ0EsbUJBQUEsYUFBQSxDQUFBLElBQUEsQ0FBQSxTQUFBO0FBQ0EsU0FOQTtBQU9BOzs7QUFHQTs7OztBQUlBLFdBQUEsSUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxLQUFBLEVBQUEsR0FBQSxFQUFBLFdBQUEsRUFBQTtBQUNBLGdCQUFBLEdBQUEsQ0FBQSxNQUFBLEVBQUEs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LElBQUEsVUFBQSxDQUFBLGtCQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsaUJBQUEsRUFBQSxZQUFBLEVBQUEsV0FBQSxFQUFBLFlBQUEsRUFBQSxNQUFBLEVBQUEsUUFBQSxFQUFBLFNBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUFBOztBQUVBLFdBQUEsTUFBQSxHQUFBLGFBQUEsTUFBQTs7QUFFQSxXQUFBLFdBQUEsR0FBQSxRQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLFNBQUE7O0FBRUEsV0FBQSxLQUFBLEdBQUEsS0FBQTs7QUFFQSxXQUFBLFVBQUEsR0FBQSxVQUFBOztBQUVBLFdBQUEsV0FBQSxHQUFBLFlBQUE7O0FBRUEsZUFBQSxPQUFBLEdBQUEsS0FBQSxHQUFBOztBQUVBLEtBSkE7OztBQVFBLGFBQUEsYUFBQSxHQUFBO0FBQ0EsZUFBQSxPQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsUUFBQSxPQUFBLFdBQUEsQ0FBQSxDQUFBLEVBQUEsQ0FBQSxDQUFBOztBQUdBLGFBQUEsSUFBQSxJQUFBLElBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxPQUFBLENBQUEsSUFBQSxDQUFBLElBQUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7OztBQUdBLGFBQUEsVUFBQSxHQUFBO0FBQ0EsZUFBQSxhQUFBLEdBQUEsRUFBQTtBQUNBLGVBQUEsV0FBQSxDQUFBLENBQUEsRUFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxZQUFBLEVBQUE7QUFDQSxpQkFBQSxJQUFBLElBQUEsSUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxTQUFBLFlBQUEsSUFBQSxTQUFBLFlBQUEsRUFBQSxVQUFBLElBQUEsQ0FBQSxJQUFBLElBQUEsQ0FBQTtBQUNBO0FBQ0EsbUJBQUEsYUFBQSxDQUFBLElBQUEsQ0FBQSxTQUFBO0FBQ0EsU0FOQTtBQU9BOzs7QUFHQTs7QUFHQSxXQUFBLGFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxPQUFB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QUFBLGFBQUE7QUFDQSxpQkFGQTtBQUdBLGFBSkE7O0FBTUEsZ0JBQUEsVUFBQSxTQUFBLE9BQUEsR0FBQTtBQUNBLDRCQUFBLGVBQUEsR0FBQSxJQUFBLENBQUEsVUFBQSxJQUFBLEVBQUE7QUFDQSwwQkFBQSxJQUFBLEdBQUEsSUFBQTtBQUNBLGlCQUZBO0FBR0EsYUFKQTs7QUFNQSxnQkFBQSxhQUFBLFNBQUEsVUFBQSxHQUFBO0FBQ0Esc0JBQUEsSUFBQSxHQUFBLElBQUE7QUFDQSxhQUZBOztBQUlBOztBQUVBLHVCQUFBLEdBQUEsQ0FBQSxZQUFBLFlBQUEsRUFBQSxPQUFBO0FBQ0EsdUJBQUEsR0FBQSxDQUFBLFlBQUEsYUFBQSxFQUFBLFVBQUE7QUFDQSx1QkFBQSxHQUFBLENBQUEsWUFBQSxjQUFBLEVBQUEsVUFBQTtBQUVBOztBQXpDQSxLQUFBO0FBNkNBLENBL0NBOztBQ0FBLElBQUEsU0FBQSxDQUFBLGVBQUEsRUFBQSxVQUFBLGVBQUEsRUFBQTs7QUFFQSxXQUFBO0FBQ0Esa0JBQUEsR0FEQTtBQUVBLHFCQUFBLHlEQUZBO0FBR0EsY0FBQSxjQUFBLEtBQUEsRUFBQTtBQUNBLGtCQUFBLFFBQUEsR0FBQSxnQkFBQSxpQkFBQSxFQUFBO0FBQ0E7QUFMQSxLQUFBO0FBUUEsQ0FWQSIsImZpbGUiOiJtYWluLmpzIiwic291cmNlc0NvbnRlbnQiOlsiJ3VzZSBzdHJpY3QnO1xud2luZG93LmFwcCA9IGFuZ3VsYXIubW9kdWxlKCdGdWxsc3RhY2tHZW5lcmF0ZWRBcHAnLCBbJ2ZzYVByZUJ1aWx0JywgJ3VpLnJvdXRlcicsICd1aS5ib290c3RyYXAnLCAnbmdBbmltYXRlJ10pO1xuXG5hcHAuY29uZmlnKGZ1bmN0aW9uICgkdXJsUm91dGVyUHJvdmlkZXIsICRsb2NhdGlvblByb3ZpZGVyKSB7XG4gICAgLy8gVGhpcyB0dXJucyBvZmYgaGFzaGJhbmcgdXJscyAoLyNhYm91dCkgYW5kIGNoYW5nZXMgaXQgdG8gc29tZXRoaW5nIG5vcm1hbCAoL2Fib3V0KVxuICAgICRsb2NhdGlvblByb3ZpZGVyLmh0bWw1TW9kZSh0cnVlKTtcbiAgICAvLyBJZiB3ZSBnbyB0byBhIFVSTCB0aGF0IHVpLXJvdXRlciBkb2Vzbid0IGhhdmUgcmVnaXN0ZXJlZCwgZ28gdG8gdGhlIFwiL1wiIHVybC5cbiAgICAkdXJsUm91dGVyUHJvdmlkZXIub3RoZXJ3aXNlKCcvJyk7XG4gICAgLy8gVHJpZ2dlciBwYWdlIHJlZnJlc2ggd2hlbiBhY2Nlc3NpbmcgYW4gT0F1dGggcm91dGVcbiAgICAkdXJsUm91dGVyUHJvdmlkZXIud2hlbignL2F1dGgvOnByb3ZpZGVyJywgZnVuY3Rpb24gKCkge1xuICAgICAgICB3aW5kb3cubG9jYXRpb24ucmVsb2FkKCk7XG4gICAgfSk7XG59KTtcblxuLy8gVGhpcyBhcHAucnVuIGlzIGZvciBjb250cm9sbGluZyBhY2Nlc3MgdG8gc3BlY2lmaWMgc3RhdGVzLlxuYXBwLnJ1bihmdW5jdGlvbiAoJHJvb3RTY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICAgLy8gVGhlIGdpdmVuIHN0YXRlIHJlcXVpcmVzIGFuIGF1dGhlbnRpY2F0ZWQgdXNlci5cbiAgICB2YXIgZGVzdGluYXRpb25TdGF0ZVJlcXVpcmVzQXV0aCA9IGZ1bmN0aW9uIChzdGF0ZSkge1xuICAgICAgICByZXR1cm4gc3RhdGUuZGF0YSAmJiBzdGF0ZS5kYXRhLmF1dGhlbnRpY2F0ZTtcbiAgICB9O1xuXG4gICAgLy8gJHN0YXRlQ2hhbmdlU3RhcnQgaXMgYW4gZXZlbnQgZmlyZWRcbiAgICAvLyB3aGVuZXZlciB0aGUgcHJvY2VzcyBvZiBjaGFuZ2luZyBhIHN0YXRlIGJlZ2lucy5cbiAgICAkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbiAoZXZlbnQsIHRvU3RhdGUsIHRvUGFyYW1zKSB7XG5cbiAgICAgICAgaWYgKCFkZXN0aW5hdGlvblN0YXRlUmVxdWlyZXNBdXRoKHRvU3RhdGUpKSB7XG4gICAgICAgICAgICAvLyBUaGUgZGVzdGluYXRpb24gc3RhdGUgZG9lcyBub3QgcmVxdWlyZSBhdXRoZW50aWNhdGlvblxuICAgICAgICAgICAgLy8gU2hvcnQgY2lyY3VpdCB3aXRoIHJldHVybi5cbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChBdXRoU2VydmljZS5pc0F1dGhlbnRpY2F0ZWQoKSkge1xuICAgICAgICAgICAgLy8gVGhlIHVzZXIgaXMgYXV0aGVudGljYXRlZC5cbiAgICAgICAgICAgIC8vIFNob3J0IGNpcmN1aXQgd2l0aCByZXR1cm4uXG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDYW5jZWwgbmF2aWdhdGluZyB0byBuZXcgc3RhdGUuXG4gICAgICAgIGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG5cbiAgICAgICAgQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCkudGhlbihmdW5jdGlvbiAodXNlcikge1xuICAgICAgICAgICAgLy8gSWYgYSB1c2VyIGlzIHJldHJpZXZlZCwgdGhlbiByZW5hdmlnYXRlIHRvIHRoZSBkZXN0aW5hdGlvblxuICAgICAgICAgICAgLy8gKHRoZSBzZWNvbmQgdGltZSwgQXV0aFNlcnZpY2UuaXNBdXRoZW50aWNhdGVkKCkgd2lsbCB3b3JrKVxuICAgICAgICAgICAgLy8gb3RoZXJ3aXNlLCBpZiBubyB1c2VyIGlzIGxvZ2dlZCBpbiwgZ28gdG8gXCJsb2dpblwiIHN0YXRlLlxuICAgICAgICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgICAgICAgICAkc3RhdGUuZ28odG9TdGF0ZS5uYW1lLCB0b1BhcmFtcyk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnbG9naW4nKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG5cbiAgICB9KTtcblxufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuXG4gICAgLy8gUmVnaXN0ZXIgb3VyICphYm91dCogc3RhdGUuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2Fib3V0Jywge1xuICAgICAgICB1cmw6ICcvYWJvdXQnLFxuICAgICAgICBjb250cm9sbGVyOiAnQWJvdXRDb250cm9sbGVyJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9hYm91dC9hYm91dC5odG1sJ1xuICAgIH0pO1xuXG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ0Fib3V0Q29udHJvbGxlcicsIGZ1bmN0aW9uICgkc2NvcGUsIEZ1bGxzdGFja1BpY3MpIHtcblxuICAgIC8vIEltYWdlcyBvZiBiZWF1dGlmdWwgRnVsbHN0YWNrIHBlb3BsZS5cbiAgICAkc2NvcGUuaW1hZ2VzID0gXy5zaHVmZmxlKEZ1bGxzdGFja1BpY3MpO1xuXG59KTsiLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdkb2NzJywge1xuICAgICAgICB1cmw6ICcvZG9jcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvZG9jcy9kb2NzLmh0bWwnXG4gICAgfSk7XG59KTtcbiIsImFwcC5jb250cm9sbGVyKCdDcmVhdGVkYkN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCAkc3RhdGUsIENyZWF0ZWRiRmFjdG9yeSkge1xuXG5cdCRzY29wZS5jcmVhdGVkREIgPSBmYWxzZTtcbiAgICAgICAgJHNjb3BlLmNvbHVtbkFycmF5ID0gW107XG5cblx0JHNjb3BlLmFkZCA9IGZ1bmN0aW9uKCkge1xuXHRcdCRzY29wZS5jb2x1bW5BcnJheS5wdXNoKCcxJyk7XG5cdH1cblxuXHQkc2NvcGUuY3JlYXRlREIgPSBmdW5jdGlvbihuYW1lKSB7XG5cdFx0Q3JlYXRlZGJGYWN0b3J5LmNyZWF0ZURCKG5hbWUpXG5cdFx0LnRoZW4oZnVuY3Rpb24oZGF0YSkge1xuXHRcdFx0JHNjb3BlLmNyZWF0ZWREQiA9IGRhdGE7XG5cdFx0fSlcblx0fVxuXG5cdCRzY29wZS5jcmVhdGVUYWJsZSA9IGZ1bmN0aW9uKHRhYmxlLCBEQil7XG5cdFx0Q3JlYXRlZGJGYWN0b3J5LmNyZWF0ZVRhYmxlKHRhYmxlLCBEQilcblx0XHRcdCRzdGF0ZS5nbygnVGFibGUnLCB7ZGJOYW1lOiAkc2NvcGUuY3JlYXRlZERCLmRiTmFtZX0sIHtyZWxvYWQ6dHJ1ZX0pXG5cdH1cbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ0NyZWF0ZWRiRmFjdG9yeScsIGZ1bmN0aW9uICgkaHR0cCkge1xuXG5cdHZhciBDcmVhdGVkYkZhY3RvcnkgPSB7fTtcblxuXHRmdW5jdGlvbiByZXNUb0RhdGEocmVzKSB7XG4gICAgICAgIHJldHVybiByZXMuZGF0YTtcbiAgICB9XG5cbiAgICBDcmVhdGVkYkZhY3RvcnkuY3JlYXRlREIgPSBmdW5jdGlvbihkYk5hbWUpIHtcbiAgICBcdHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL21hc3RlcmRiJywgZGJOYW1lKVxuICAgIFx0LnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgQ3JlYXRlZGJGYWN0b3J5LmNyZWF0ZVRhYmxlID0gZnVuY3Rpb24odGFibGUsIGNyZWF0ZWREQikge1xuICAgIHRhYmxlLmRiTmFtZSA9IGNyZWF0ZWREQi5kYk5hbWU7XG4gICAgcmV0dXJuICRodHRwLnBvc3QoJy9hcGkvY2xpZW50ZGInLCB0YWJsZSlcbiAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgfVxuXG5cdHJldHVybiBDcmVhdGVkYkZhY3Rvcnk7IFxufSlcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2NyZWF0ZWRiJywge1xuICAgICAgICB1cmw6ICcvY3JlYXRlZGInLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2NyZWF0ZWRiL2NyZWF0ZWRiLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnQ3JlYXRlZGJDdHJsJyxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICBcdGxvZ2dlZEluVXNlcjogZnVuY3Rpb24oQXV0aFNlcnZpY2UpIHtcbiAgICAgICAgXHRcdHJldHVybiBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKTtcbiAgICAgICAgXHR9XG4gICAgICAgIH1cbiAgICB9KTtcblxufSk7IiwiKGZ1bmN0aW9uICgpIHtcblxuICAgICd1c2Ugc3RyaWN0JztcblxuICAgIC8vIEhvcGUgeW91IGRpZG4ndCBmb3JnZXQgQW5ndWxhciEgRHVoLWRveS5cbiAgICBpZiAoIXdpbmRvdy5hbmd1bGFyKSB0aHJvdyBuZXcgRXJyb3IoJ0kgY2FuXFwndCBmaW5kIEFuZ3VsYXIhJyk7XG5cbiAgICB2YXIgYXBwID0gYW5ndWxhci5tb2R1bGUoJ2ZzYVByZUJ1aWx0JywgW10pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ1NvY2tldCcsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKCF3aW5kb3cuaW8pIHRocm93IG5ldyBFcnJvcignc29ja2V0LmlvIG5vdCBmb3VuZCEnKTtcbiAgICAgICAgcmV0dXJuIHdpbmRvdy5pbyh3aW5kb3cubG9jYXRpb24ub3JpZ2luKTtcbiAgICB9KTtcblxuICAgIC8vIEFVVEhfRVZFTlRTIGlzIHVzZWQgdGhyb3VnaG91dCBvdXIgYXBwIHRvXG4gICAgLy8gYnJvYWRjYXN0IGFuZCBsaXN0ZW4gZnJvbSBhbmQgdG8gdGhlICRyb290U2NvcGVcbiAgICAvLyBmb3IgaW1wb3J0YW50IGV2ZW50cyBhYm91dCBhdXRoZW50aWNhdGlvbiBmbG93LlxuICAgIGFwcC5jb25zdGFudCgnQVVUSF9FVkVOVFMnLCB7XG4gICAgICAgIGxvZ2luU3VjY2VzczogJ2F1dGgtbG9naW4tc3VjY2VzcycsXG4gICAgICAgIGxvZ2luRmFpbGVkOiAnYXV0aC1sb2dpbi1mYWlsZWQnLFxuICAgICAgICBsb2dvdXRTdWNjZXNzOiAnYXV0aC1sb2dvdXQtc3VjY2VzcycsXG4gICAgICAgIHNlc3Npb25UaW1lb3V0OiAnYXV0aC1zZXNzaW9uLXRpbWVvdXQnLFxuICAgICAgICBub3RBdXRoZW50aWNhdGVkOiAnYXV0aC1ub3QtYXV0aGVudGljYXRlZCcsXG4gICAgICAgIG5vdEF1dGhvcml6ZWQ6ICdhdXRoLW5vdC1hdXRob3JpemVkJ1xuICAgIH0pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ0F1dGhJbnRlcmNlcHRvcicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCAkcSwgQVVUSF9FVkVOVFMpIHtcbiAgICAgICAgdmFyIHN0YXR1c0RpY3QgPSB7XG4gICAgICAgICAgICA0MDE6IEFVVEhfRVZFTlRTLm5vdEF1dGhlbnRpY2F0ZWQsXG4gICAgICAgICAgICA0MDM6IEFVVEhfRVZFTlRTLm5vdEF1dGhvcml6ZWQsXG4gICAgICAgICAgICA0MTk6IEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LFxuICAgICAgICAgICAgNDQwOiBBVVRIX0VWRU5UUy5zZXNzaW9uVGltZW91dFxuICAgICAgICB9O1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KHN0YXR1c0RpY3RbcmVzcG9uc2Uuc3RhdHVzXSwgcmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVzcG9uc2UpXG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgfSk7XG5cbiAgICBhcHAuY29uZmlnKGZ1bmN0aW9uICgkaHR0cFByb3ZpZGVyKSB7XG4gICAgICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goW1xuICAgICAgICAgICAgJyRpbmplY3RvcicsXG4gICAgICAgICAgICBmdW5jdGlvbiAoJGluamVjdG9yKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRpbmplY3Rvci5nZXQoJ0F1dGhJbnRlcmNlcHRvcicpO1xuICAgICAgICAgICAgfVxuICAgICAgICBdKTtcbiAgICB9KTtcblxuICAgIGFwcC5zZXJ2aWNlKCdBdXRoU2VydmljZScsIGZ1bmN0aW9uICgkaHR0cCwgU2Vzc2lvbiwgJHJvb3RTY29wZSwgQVVUSF9FVkVOVFMsICRxKSB7XG5cbiAgICAgICAgZnVuY3Rpb24gb25TdWNjZXNzZnVsTG9naW4ocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHZhciBkYXRhID0gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgICAgIFNlc3Npb24uY3JlYXRlKGRhdGEuaWQsIGRhdGEudXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3QoQVVUSF9FVkVOVFMubG9naW5TdWNjZXNzKTtcbiAgICAgICAgICAgIHJldHVybiBkYXRhLnVzZXI7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBVc2VzIHRoZSBzZXNzaW9uIGZhY3RvcnkgdG8gc2VlIGlmIGFuXG4gICAgICAgIC8vIGF1dGhlbnRpY2F0ZWQgdXNlciBpcyBjdXJyZW50bHkgcmVnaXN0ZXJlZC5cbiAgICAgICAgdGhpcy5pc0F1dGhlbnRpY2F0ZWQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gISFTZXNzaW9uLnVzZXI7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5nZXRMb2dnZWRJblVzZXIgPSBmdW5jdGlvbiAoZnJvbVNlcnZlcikge1xuXG4gICAgICAgICAgICAvLyBJZiBhbiBhdXRoZW50aWNhdGVkIHNlc3Npb24gZXhpc3RzLCB3ZVxuICAgICAgICAgICAgLy8gcmV0dXJuIHRoZSB1c2VyIGF0dGFjaGVkIHRvIHRoYXQgc2Vzc2lvblxuICAgICAgICAgICAgLy8gd2l0aCBhIHByb21pc2UuIFRoaXMgZW5zdXJlcyB0aGF0IHdlIGNhblxuICAgICAgICAgICAgLy8gYWx3YXlzIGludGVyZmFjZSB3aXRoIHRoaXMgbWV0aG9kIGFzeW5jaHJvbm91c2x5LlxuXG4gICAgICAgICAgICAvLyBPcHRpb25hbGx5LCBpZiB0cnVlIGlzIGdpdmVuIGFzIHRoZSBmcm9tU2VydmVyIHBhcmFtZXRlcixcbiAgICAgICAgICAgIC8vIHRoZW4gdGhpcyBjYWNoZWQgdmFsdWUgd2lsbCBub3QgYmUgdXNlZC5cblxuICAgICAgICAgICAgaWYgKHRoaXMuaXNBdXRoZW50aWNhdGVkKCkgJiYgZnJvbVNlcnZlciAhPT0gdHJ1ZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS53aGVuKFNlc3Npb24udXNlcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIE1ha2UgcmVxdWVzdCBHRVQgL3Nlc3Npb24uXG4gICAgICAgICAgICAvLyBJZiBpdCByZXR1cm5zIGEgdXNlciwgY2FsbCBvblN1Y2Nlc3NmdWxMb2dpbiB3aXRoIHRoZSByZXNwb25zZS5cbiAgICAgICAgICAgIC8vIElmIGl0IHJldHVybnMgYSA0MDEgcmVzcG9uc2UsIHdlIGNhdGNoIGl0IGFuZCBpbnN0ZWFkIHJlc29sdmUgdG8gbnVsbC5cbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9zZXNzaW9uJykudGhlbihvblN1Y2Nlc3NmdWxMb2dpbikuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLnNpZ251cCA9IGZ1bmN0aW9uKGNyZWRlbnRpYWxzKXtcbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvc2lnbnVwJywgY3JlZGVudGlhbHMpXG4gICAgICAgICAgICAudGhlbihvblN1Y2Nlc3NmdWxMb2dpbilcbiAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdCh7IG1lc3NhZ2U6ICdJbnZhbGlkIHNpZ251cCBjcmVkZW50aWFscy4nIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5sb2dpbiA9IGZ1bmN0aW9uIChjcmVkZW50aWFscykge1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9sb2dpbicsIGNyZWRlbnRpYWxzKVxuICAgICAgICAgICAgICAgIC50aGVuKG9uU3VjY2Vzc2Z1bExvZ2luKVxuICAgICAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QoeyBtZXNzYWdlOiAnSW52YWxpZCBsb2dpbiBjcmVkZW50aWFscy4nIH0pO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2xvZ291dCcpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIFNlc3Npb24uZGVzdHJveSgpO1xuICAgICAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChBVVRIX0VWRU5UUy5sb2dvdXRTdWNjZXNzKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuXG4gICAgfSk7XG5cbiAgICBhcHAuc2VydmljZSgnU2Vzc2lvbicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBVVRIX0VWRU5UUykge1xuXG4gICAgICAgIHZhciBzZWxmID0gdGhpcztcblxuICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5ub3RBdXRoZW50aWNhdGVkLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBzZWxmLmRlc3Ryb3koKTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHNlbGYuZGVzdHJveSgpO1xuICAgICAgICB9KTtcblxuICAgICAgICB0aGlzLmlkID0gbnVsbDtcbiAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcblxuICAgICAgICB0aGlzLmNyZWF0ZSA9IGZ1bmN0aW9uIChzZXNzaW9uSWQsIHVzZXIpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBzZXNzaW9uSWQ7XG4gICAgICAgICAgICB0aGlzLnVzZXIgPSB1c2VyO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMuZGVzdHJveSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBudWxsO1xuICAgICAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcbiAgICAgICAgfTtcblxuICAgIH0pO1xuXG59KSgpO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnbGFuZGluZ1BhZ2UnLCB7XG4gICAgICAgIHVybDogJy8nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2xhbmRpbmdQYWdlL2xhbmRpbmdQYWdlLmh0bWwnXG4gICAgICAgIH1cbiAgICApO1xuXG59KTsiLCJhcHAuY29udHJvbGxlcignSG9tZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBhbGxEYnMsICRzdGF0ZSkge1xuXG5cdCRzY29wZS5hbGxEYnMgPSBhbGxEYnM7XG59KTtcbiIsImFwcC5mYWN0b3J5KCdIb21lRmFjdG9yeScsIGZ1bmN0aW9uICgkaHR0cCkge1xuXG5cdHZhciBIb21lRmFjdG9yeSA9IHt9O1xuXG5cdGZ1bmN0aW9uIHJlc1RvRGF0YShyZXMpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5kYXRhO1xuICAgIH1cblxuICAgIEhvbWVGYWN0b3J5LmdldEFsbERicyA9IGZ1bmN0aW9uKCl7XG4gICAgXHRyZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL21hc3RlcmRiJylcbiAgICBcdC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgICBIb21lRmFjdG9yeS5kZWxldGVEQiA9IGZ1bmN0aW9uKG5hbWUpe1xuICAgIFx0cmV0dXJuICRodHRwLmRlbGV0ZSgnL2FwaS9tYXN0ZXJkYi8nICsgbmFtZSlcbiAgICBcdC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cblx0cmV0dXJuIEhvbWVGYWN0b3J5OyBcbn0pIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnSG9tZScsIHtcbiAgICAgICAgdXJsOiAnL2hvbWUnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL0hvbWUvSG9tZS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0hvbWVDdHJsJyxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICBcdGFsbERiczogZnVuY3Rpb24oSG9tZUZhY3Rvcnkpe1xuICAgICAgICBcdFx0cmV0dXJuIEhvbWVGYWN0b3J5LmdldEFsbERicygpO1xuICAgICAgICBcdH0sXG4gICAgICAgICAgICBsb2dnZWRJblVzZXI6IGZ1bmN0aW9uIChBdXRoU2VydmljZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pO1xufSk7IiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdtZW1iZXJzT25seScsIHtcbiAgICAgICAgdXJsOiAnL21lbWJlcnMtYXJlYScsXG4gICAgICAgIHRlbXBsYXRlOiAnPGltZyBuZy1yZXBlYXQ9XCJpdGVtIGluIHN0YXNoXCIgd2lkdGg9XCIzMDBcIiBuZy1zcmM9XCJ7eyBpdGVtIH19XCIgLz4nLFxuICAgICAgICBjb250cm9sbGVyOiBmdW5jdGlvbiAoJHNjb3BlLCBTZWNyZXRTdGFzaCkge1xuICAgICAgICAgICAgU2VjcmV0U3Rhc2guZ2V0U3Rhc2goKS50aGVuKGZ1bmN0aW9uIChzdGFzaCkge1xuICAgICAgICAgICAgICAgICRzY29wZS5zdGFzaCA9IHN0YXNoO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0sXG4gICAgICAgIC8vIFRoZSBmb2xsb3dpbmcgZGF0YS5hdXRoZW50aWNhdGUgaXMgcmVhZCBieSBhbiBldmVudCBsaXN0ZW5lclxuICAgICAgICAvLyB0aGF0IGNvbnRyb2xzIGFjY2VzcyB0byB0aGlzIHN0YXRlLiBSZWZlciB0byBhcHAuanMuXG4gICAgICAgIGRhdGE6IHtcbiAgICAgICAgICAgIGF1dGhlbnRpY2F0ZTogdHJ1ZVxuICAgICAgICB9XG4gICAgfSk7XG5cbn0pO1xuXG5hcHAuZmFjdG9yeSgnU2VjcmV0U3Rhc2gnLCBmdW5jdGlvbiAoJGh0dHApIHtcblxuICAgIHZhciBnZXRTdGFzaCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9tZW1iZXJzL3NlY3JldC1zdGFzaCcpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgfSk7XG4gICAgfTtcblxuICAgIHJldHVybiB7XG4gICAgICAgIGdldFN0YXNoOiBnZXRTdGFzaFxuICAgIH07XG5cbn0pOyIsImFwcC5jb25maWcoZnVuY3Rpb24oJHN0YXRlUHJvdmlkZXIpIHtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdsb2dpbicsIHtcbiAgICAgICAgdXJsOiAnL2xvZ2luJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9sb2dpbi9sb2dpbi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0xvZ2luQ3RybCdcbiAgICB9KTtcblxufSk7XG5cbmFwcC5jb250cm9sbGVyKCdMb2dpbkN0cmwnLCBmdW5jdGlvbigkc2NvcGUsIEF1dGhTZXJ2aWNlLCAkc3RhdGUpIHtcblxuICAgICRzY29wZS5sb2dpbiA9IHt9O1xuICAgICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgICAkc2NvcGUuc2VuZExvZ2luID0gZnVuY3Rpb24obG9naW5JbmZvKSB7XG5cbiAgICAgICAgJHNjb3BlLmVycm9yID0gbnVsbDtcblxuICAgICAgICBBdXRoU2VydmljZS5sb2dpbihsb2dpbkluZm8pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oJ0hvbWUnKTtcbiAgICAgICAgfSkuY2F0Y2goZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAkc2NvcGUuZXJyb3IgPSAnSW52YWxpZCBsb2dpbiBjcmVkZW50aWFscy4nO1xuICAgICAgICB9KTtcblxuICAgIH07XG5cbn0pO1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG5hcHAuZGlyZWN0aXZlKCdvYXV0aEJ1dHRvbicsIGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIHtcbiAgICBzY29wZToge1xuICAgICAgcHJvdmlkZXJOYW1lOiAnQCdcbiAgICB9LFxuICAgIHJlc3RyaWN0OiAnRScsXG4gICAgdGVtcGxhdGVVcmw6ICcvanMvb2F1dGgvb2F1dGgtYnV0dG9uLmh0bWwnXG4gIH1cbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdzaWdudXAnLCB7XG4gICAgICAgIHVybDogJy9zaWdudXAnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3NpZ251cC9zaWdudXAuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdTaWdudXBDdHJsJ1xuICAgIH0pO1xuXG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ1NpZ251cEN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBBdXRoU2VydmljZSwgJHN0YXRlKSB7XG5cbiAgICAkc2NvcGUuc2lnbnVwID0ge307XG4gICAgJHNjb3BlLmVycm9yID0gbnVsbDtcblxuICAgICRzY29wZS5zZW5kU2lnbnVwID0gZnVuY3Rpb24gKHNpZ251cEluZm8pIHtcbiAgICAgICAgJHNjb3BlLmVycm9yID0gbnVsbDtcbiAgICAgICAgQXV0aFNlcnZpY2Uuc2lnbnVwKHNpZ251cEluZm8pLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKCdob21lJyk7XG4gICAgICAgIH0pLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICRzY29wZS5lcnJvciA9ICdPb3BzLCBjYW5ub3Qgc2lnbiB1cCB3aXRoIHRob3NlIGNyZWRlbnRpYWxzLic7XG4gICAgICAgIH0pO1xuXG4gICAgfTtcblxufSk7XG4iLCJhcHAuY29udHJvbGxlcignQXNzb2NpYXRpb25JbnN0YW5jZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCAkdWliTW9kYWxJbnN0YW5jZSwgZm9yZWlnbkNvbHMsIFRhYmxlRmFjdG9yeSwgSG9tZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgJHN0YXRlLCBmb3JUYWJsZSwgZm9yVGFibGVOYW1lLCBjdXJyVGFibGUsIGNvbE5hbWUsIGlkMSkge1xuXG4gICRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lO1xuXG4gICRzY29wZS5zaW5nbGVUYWJsZSA9IGZvclRhYmxlO1xuXG4gICRzY29wZS5UYWJsZU5hbWUgPSBmb3JUYWJsZU5hbWU7XG5cbiAgJHNjb3BlLmN1cnJUYWJsZSA9IGN1cnJUYWJsZTtcblxuICAkc2NvcGUuY29sTmFtZSA9IGNvbE5hbWU7XG5cbiAgJHNjb3BlLmlkMSA9IGlkMTtcblxuICAkc2NvcGUuc2V0U2VsZWN0ZWQgPSBmdW5jdGlvbigpe1xuXG4gICAgJHNjb3BlLmN1cnJSb3cgPSB0aGlzLnJvdztcbiAgICBjb25zb2xlLmxvZygkc2NvcGUuY3VyclJvdyk7XG4gIH1cblxuIFxuXG4gIGZ1bmN0aW9uIENyZWF0ZUNvbHVtbnMoKXtcbiAgICAkc2NvcGUuY29sdW1ucyA9IFtdO1xuICAgIHZhciB0YWJsZSA9IGZvclRhYmxlWzBdO1xuXG5cbiAgICBmb3IodmFyIHByb3AgaW4gdGFibGUpe1xuICAgICAgaWYocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jyl7XG4gICAgICAgICRzY29wZS5jb2x1bW5zLnB1c2gocHJvcCk7ICBcbiAgICAgIH0gXG4gICAgfVxuICB9XG5cbiAgICBDcmVhdGVDb2x1bW5zKCk7XG5cblxuICAgIC8vdGhpcyBmdW5jdGlvbiB3aWxsIHJlIHJ1biB3aGVuIHRoZSBmaWx0ZXIgZnVuY3Rpb24gaXMgaW52b2tlZCwgaW4gb3JkZXIgdG8gcmVwb3B1bGF0ZSB0aGUgdGFibGVcbiAgICBmdW5jdGlvbiBDcmVhdGVSb3dzKCkge1xuICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheSA9IFtdO1xuICAgICAgICBmb3JUYWJsZS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgdmFyIHJvd1ZhbHVlcyA9IFtdO1xuICAgICAgICAgICAgZm9yICh2YXIgcHJvcCBpbiByb3cpIHtcbiAgICAgICAgICAgICAgICBpZiAocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jykgcm93VmFsdWVzLnB1c2gocm93W3Byb3BdKVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkucHVzaChyb3dWYWx1ZXMpXG4gICAgICAgIH0pXG4gICAgfVxuXG4gICAgLy8gU29ydCB0aGUgdmFsdWVzIGluIHNpbmdsZVRhYmxlIHNvIHRoYXQgYWxsIHRoZSB2YWx1ZXMgZm9yIGEgZ2l2ZW4gcm93IGFyZSBncm91cGVkXG4gICAgQ3JlYXRlUm93cygpO1xuXG5cbiAgJHNjb3BlLnNldEZvcmVpZ25LZXkgPSBmdW5jdGlvbihkYk5hbWUsIHRibE5hbWUsIGNvbE5hbWUsIGlkMSwgaWQyKXtcbiAgICAkdWliTW9kYWxJbnN0YW5jZS5jbG9zZSgpO1xuICAgIFRhYmxlRmFjdG9yeS5zZXRGb3JlaWduS2V5KGRiTmFtZSwgdGJsTmFtZSwgY29sTmFtZSwgaWQxLCBpZDIpXG4gICAgLnRoZW4oZnVuY3Rpb24oKXtcbiAgICAgICAgJHN0YXRlLmdvKCdUYWJsZS5TaW5nbGUnLCB7IGRiTmFtZTogJHNjb3BlLmRiTmFtZSwgdGFibGVOYW1lOiAkc2NvcGUuY3VyclRhYmxlIH0sIHsgcmVsb2FkOiB0cnVlIH0pXG4gICAgfSlcbiAgfVxuXG5cblxuICAkc2NvcGUub2sgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoJHNjb3BlLnNlbGVjdGVkLml0ZW0pO1xuICB9O1xuXG4gICRzY29wZS5jYW5jZWwgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuZGlzbWlzcygnY2FuY2VsJyk7XG4gIH07XG59KTsiLCJhcHAuY29udHJvbGxlcignZGVsZXRlREJDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHVpYk1vZGFsLCAkbG9nKSB7XG5cbiAgJHNjb3BlLml0ZW1zID0gWydpdGVtMScsICdpdGVtMicsICdpdGVtMyddO1xuXG4gICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9IHRydWU7XG5cbiAgJHNjb3BlLm9wZW4gPSBmdW5jdGlvbiAoc2l6ZSkge1xuXG4gICAgdmFyIG1vZGFsSW5zdGFuY2UgPSAkdWliTW9kYWwub3Blbih7XG4gICAgICBhbmltYXRpb246ICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCxcbiAgICAgIHRlbXBsYXRlVXJsOiAnZGVsZXRlREJDb250ZW50Lmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ2RlbGV0ZURCSW5zdGFuY2VDdHJsJyxcbiAgICAgIHNpemU6IHNpemUsXG4gICAgICByZXNvbHZlOiB7XG4gICAgICAgIGl0ZW1zOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgcmV0dXJuICRzY29wZS5pdGVtcztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbiAoc2VsZWN0ZWRJdGVtKSB7XG4gICAgICAkc2NvcGUuc2VsZWN0ZWQgPSBzZWxlY3RlZEl0ZW07XG4gICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgJGxvZy5pbmZvKCdNb2RhbCBkaXNtaXNzZWQgYXQ6ICcgKyBuZXcgRGF0ZSgpKTtcbiAgICB9KTtcbiAgfTtcblxuICAkc2NvcGUudG9nZ2xlQW5pbWF0aW9uID0gZnVuY3Rpb24gKCkge1xuICAgICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9ICEkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQ7XG4gIH07XG5cbn0pO1xuXG5hcHAuY29udHJvbGxlcignZGVsZXRlREJJbnN0YW5jZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCAkdWliTW9kYWxJbnN0YW5jZSwgaXRlbXMsIFRhYmxlRmFjdG9yeSwgSG9tZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgJHN0YXRlKSB7XG5cblxuICAkc2NvcGUuZHJvcERiVGV4dCA9ICdEUk9QIERBVEFCQVNFJ1xuICAkc2NvcGUuZGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZTtcblxuICAkc2NvcGUuZGVsZXRlVGhlRGIgPSBmdW5jdGlvbigpe1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmNsb3NlKCRzY29wZS5zZWxlY3RlZC5pdGVtKTtcbiAgICBUYWJsZUZhY3RvcnkuZGVsZXRlRGIoJHNjb3BlLmRiTmFtZSlcbiAgICAudGhlbihmdW5jdGlvbigpe1xuICAgICAgSG9tZUZhY3RvcnkuZGVsZXRlREIoJHNjb3BlLmRiTmFtZSlcbiAgICB9KVxuICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgJHN0YXRlLmdvKCdIb21lJywge30sIHtyZWxvYWQgOiB0cnVlfSlcbiAgICB9KVxuICB9XG5cbiAgJHNjb3BlLml0ZW1zID0gaXRlbXM7XG4gICRzY29wZS5zZWxlY3RlZCA9IHtcbiAgICBpdGVtOiAkc2NvcGUuaXRlbXNbMF1cbiAgfTtcblxuICAkc2NvcGUub2sgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoJHNjb3BlLnNlbGVjdGVkLml0ZW0pO1xuICB9O1xuXG4gICRzY29wZS5jYW5jZWwgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuZGlzbWlzcygnY2FuY2VsJyk7XG4gIH07XG59KTsiLCJhcHAuY29udHJvbGxlcignRGVsZXRlRGJDdHJsJywgZnVuY3Rpb24gKCRzY29wZSkge1xuXG4gICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9IHRydWU7XG5cbiAgJHNjb3BlLm9wZW4gPSBmdW5jdGlvbiAoc2l6ZSkge1xuXG4gICAgdmFyIG1vZGFsSW5zdGFuY2UgPSAkdWliTW9kYWwub3Blbih7XG4gICAgICBhbmltYXRpb246ICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCxcbiAgICAgIHRlbXBsYXRlVXJsOiAnZGVsZXRlRGJDb250ZW50Lmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ0RlbGV0ZURiSW5zdGFuY2VDdHJsJyxcbiAgICAgIHNpemU6IHNpemUsXG4gICAgICByZXNvbHZlOiB7XG4gICAgICAgIGl0ZW1zOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgcmV0dXJuICRzY29wZS5pdGVtcztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbiAoc2VsZWN0ZWRJdGVtKSB7XG4gICAgICAkc2NvcGUuc2VsZWN0ZWQgPSBzZWxlY3RlZEl0ZW07XG4gICAgfSwgZnVuY3Rpb24gKCkge1xuICAgICAgJGxvZy5pbmZvKCdNb2RhbCBkaXNtaXNzZWQgYXQ6ICcgKyBuZXcgRGF0ZSgpKTtcbiAgICB9KTtcbiAgfTtcblxufSk7XG5cblxuYXBwLmNvbnRyb2xsZXIoJ0RlbGV0ZURiSW5zdGFuY2VDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHVpYk1vZGFsSW5zdGFuY2UsIGl0ZW1zLCAkc3RhdGVQYXJhbXMsIFRhYmxlRmFjdG9yeSkge1xuXG4gICRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lXG5cbiAgJHNjb3BlLmRyb3BEYXRhYmFzZSA9ICdEUk9QIERBVEFCQVNFJ1xuXG4gICRzY29wZS5kZWxldGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgVGFibGVGYWN0b3J5LmRlbGV0ZURiKCRzY29wZS5kYk5hbWUpXG4gICAgLy8gJHN0YXRlLmdvKCdIb21lJywge30sIHtyZWxvYWQgOiB0cnVlfSlcbiAgfTtcblxuICAkc2NvcGUuY2FuY2VsID0gZnVuY3Rpb24gKCkge1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmRpc21pc3MoJ2NhbmNlbCcpO1xuICB9O1xufSk7IiwiYXBwLmNvbnRyb2xsZXIoJ0pvaW5UYWJsZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgam9pblRhYmxlKSB7XG5cbiAgICAkc2NvcGUuam9pblRhYmxlID0gam9pblRhYmxlO1xuXG5cblx0ZnVuY3Rpb24gQ3JlYXRlQ29sdW1ucygpe1xuXHRcdCRzY29wZS5jb2x1bW5zID0gW107XG5cdFx0dmFyIHRhYmxlID0gJHNjb3BlLmpvaW5UYWJsZVswXTtcblxuXG5cdFx0Zm9yKHZhciBwcm9wIGluIHRhYmxlKXtcblx0XHRcdGlmKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpe1xuXHRcdFx0XHQkc2NvcGUuY29sdW1ucy5wdXNoKHByb3ApO1x0XG5cdFx0XHR9IFxuXHRcdH1cblx0fVxuXG4gICAgQ3JlYXRlQ29sdW1ucygpO1xuXG5cbiAgICAvL3RoaXMgZnVuY3Rpb24gd2lsbCByZSBydW4gd2hlbiB0aGUgZmlsdGVyIGZ1bmN0aW9uIGlzIGludm9rZWQsIGluIG9yZGVyIHRvIHJlcG9wdWxhdGUgdGhlIHRhYmxlXG4gICAgZnVuY3Rpb24gQ3JlYXRlUm93cygpIHtcbiAgICBcdHZhciBhbGlhcztcbiAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkgPSBbXTtcbiAgICAgICAgam9pblRhYmxlLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICB2YXIgcm93VmFsdWVzID0gW107XG4gICAgICAgICAgICBmb3IgKHZhciBwcm9wIGluIHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKSByb3dWYWx1ZXMucHVzaChyb3dbcHJvcF0pXG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheS5wdXNoKHJvd1ZhbHVlcylcbiAgICAgICAgfSlcbiAgICB9XG5cbiAgICAvLyBTb3J0IHRoZSB2YWx1ZXMgaW4gc2luZ2xlVGFibGUgc28gdGhhdCBhbGwgdGhlIHZhbHVlcyBmb3IgYSBnaXZlbiByb3cgYXJlIGdyb3VwZWRcbiAgICBDcmVhdGVSb3dzKCk7XG5cblxufSkiLCJhcHAuY29udHJvbGxlcignUXVlcnlUYWJsZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuXG4gICAgJHNjb3BlLnFGaWx0ZXIgPSBmdW5jdGlvbihyZWZlcmVuY2VTdHJpbmcsIHZhbCl7XG4gICAgICAgIGlmKCFyZWZlcmVuY2VTdHJpbmcpIHJldHVybiB0cnVlO1xuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIGZvcih2YXIgcHJvcCBpbiB2YWwpe1xuICAgICAgICAgICAgICAgIHZhciBjZWxsVmFsID0gdmFsW3Byb3BdLnRvU3RyaW5nKCkudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgICAgICB2YXIgc2VhcmNoVmFsID0gcmVmZXJlbmNlU3RyaW5nLnRvU3RyaW5nKCkudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhjZWxsVmFsLCBzZWFyY2hWYWwsIGNlbGxWYWwuaW5kZXhPZihzZWFyY2hWYWwpICE9PSAtMSlcbiAgICAgICAgICAgICAgICBpZihjZWxsVmFsLmluZGV4T2Yoc2VhcmNoVmFsKSAhPT0gLTEpIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbn0pIiwiYXBwLmNvbnRyb2xsZXIoJ1NpbmdsZVRhYmxlQ3RybCcsIGZ1bmN0aW9uKCRzY29wZSwgVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMsIHNpbmdsZVRhYmxlLCAkd2luZG93LCAkc3RhdGUsICR1aWJNb2RhbCwgYXNzb2NpYXRpb25zLCAkbG9nKSB7XG5cbiAgICAvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vUHV0dGluZyBzdHVmZiBvbiBzY29wZS8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgICRzY29wZS50aGVEYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lO1xuICAgICRzY29wZS50aGVUYWJsZU5hbWUgPSAkc3RhdGVQYXJhbXMudGFibGVOYW1lO1xuICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHNpbmdsZVRhYmxlWzBdO1xuICAgICRzY29wZS5zZWxlY3RlZEFsbCA9IGZhbHNlO1xuICAgICRzY29wZS5hc3NvY2lhdGlvbnMgPSBhc3NvY2lhdGlvbnM7XG5cbiAgICBpZigkc2NvcGUuYXNzb2NpYXRpb25zLmxlbmd0aD4wKSB7XG4gICAgICAgIGlmKCRzY29wZS5hc3NvY2lhdGlvbnNbMF1bJ1Rocm91Z2gnXSA9PT0gJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKCdUYWJsZS5UaHJvdWdoJywge2RiTmFtZSA6ICRzdGF0ZVBhcmFtcy5kYk5hbWUsIHRhYmxlTmFtZSA6ICRzdGF0ZVBhcmFtcy50YWJsZU5hbWV9KVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZm9yZWlnbkNvbHVtbk9iaigpIHtcbiAgICAgICAgdmFyIGZvcmVpZ25Db2xzID0ge307XG4gICAgICAgICRzY29wZS5hc3NvY2lhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIGlmIChyb3cuVGFibGUxID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmIHJvdy5SZWxhdGlvbnNoaXAxID09PSAnaGFzT25lJykge1xuICAgICAgICAgICAgICAgIGZvcmVpZ25Db2xzW3Jvdy5BbGlhczFdID0gcm93LlRhYmxlMlxuICAgICAgICAgICAgfSBlbHNlIGlmIChyb3cuVGFibGUyID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmIHJvdy5SZWxhdGlvbnNoaXAyID09PSAnaGFzT25lJykge1xuICAgICAgICAgICAgICAgIGZvcmVpZ25Db2xzW3Jvdy5BbGlhczJdID0gcm93LlRhYmxlMVxuICAgICAgICAgICAgfVxuICAgICAgICB9KVxuICAgICAgICAkc2NvcGUuZm9yZWlnbkNvbHMgPSBmb3JlaWduQ29scztcbiAgICB9XG5cbiAgICBmb3JlaWduQ29sdW1uT2JqKCk7XG5cblxuICAgICRzY29wZS5jdXJyZW50VGFibGUgPSAkc3RhdGVQYXJhbXM7XG5cbiAgICAkc2NvcGUubXlJbmRleCA9IDE7XG5cbiAgICAkc2NvcGUuaWRzID0gJHNjb3BlLnNpbmdsZVRhYmxlLm1hcChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgcmV0dXJuIHJvdy5pZDtcbiAgICB9KVxuXG4gICAgLy9kZWxldGUgYSByb3cgXG4gICAgJHNjb3BlLnNob3dEZWxldGUgPSBmYWxzZTtcbiAgICAkc2NvcGUudG9nZ2xlRGVsZXRlID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICRzY29wZS5zaG93RGVsZXRlID0gISRzY29wZS5zaG93RGVsZXRlXG4gICAgfVxuXG4gICAgJHNjb3BlLmRlbGV0ZVNlbGVjdGVkID0gZnVuY3Rpb24oZGIsIHRhYmxlLCBpbnN0YW5jZUFycmF5KSB7XG4gICAgICAgIGluc3RhbmNlQXJyYXkuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIGlmIChyb3cuc2VsZWN0ZWQpIHtcbiAgICAgICAgICAgICAgICBUYWJsZUZhY3RvcnkucmVtb3ZlUm93KGRiLCB0YWJsZSwgcm93Wyd2YWx1ZXMnXVswXVsndmFsdWUnXSlcbiAgICAgICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB9XG4gICAgICAgIH0pXG4gICAgICAgICRzY29wZS5zaG93RGVsZXRlID0gZmFsc2U7XG4gICAgfVxuXG4gICAgJHNjb3BlLnNlbGVjdEFsbCA9IGZ1bmN0aW9uKGluc3RhbmNlQXJyYXkpIHtcbiAgICAgICAgaWYgKCRzY29wZS5zZWxlY3RlZEFsbCkge1xuICAgICAgICAgICAgaW5zdGFuY2VBcnJheS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgICAgIHJvdy5zZWxlY3RlZCA9IHRydWU7XG4gICAgICAgICAgICB9KVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgaW5zdGFuY2VBcnJheS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgICAgIHJvdy5zZWxlY3RlZCA9IGZhbHNlO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS51bmNoZWNrU2VsZWN0QWxsID0gZnVuY3Rpb24oaW5zdGFuY2VBcnJheSkge1xuICAgICAgICBpZiAoJHNjb3BlLnNlbGVjdGVkQWxsID09PSB0cnVlKSB7XG4gICAgICAgICAgICAkc2NvcGUuc2VsZWN0ZWRBbGwgPSBmYWxzZTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS5yZW1vdmVSb3cgPSBmdW5jdGlvbihkYiwgdGFibGUsIHJvdykge1xuICAgICAgICBUYWJsZUZhY3RvcnkucmVtb3ZlUm93KGRiLCB0YWJsZSwgcm93KVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0O1xuICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgIH0pXG4gICAgfVxuXG4gICAgJHNjb3BlLnJlbW92ZUNvbHVtbiA9IGZ1bmN0aW9uKGRiLCB0YWJsZSwgY29sdW1uTmFtZSkge1xuICAgICAgICBUYWJsZUZhY3RvcnkucmVtb3ZlQ29sdW1uKGRiLCB0YWJsZSwgY29sdW1uTmFtZSlcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHJlc3VsdDtcbiAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICAgICAgQ3JlYXRlQ29sdW1ucygpO1xuICAgICAgICAgICAgfSlcbiAgICB9XG5cbiAgICAkc2NvcGUubmV3Um93ID0gZnVuY3Rpb24oZGIsIHRhYmxlLCBhcnIpIHtcbiAgICAgICAgdmFyIGFsbElkcyA9IFtdO1xuICAgICAgICBhcnIuZm9yRWFjaChmdW5jdGlvbihyb3dEYXRhKSB7XG4gICAgICAgICAgICBhbGxJZHMucHVzaChyb3dEYXRhLnZhbHVlc1swXS52YWx1ZSlcbiAgICAgICAgfSlcbiAgICAgICAgdmFyIHNvcnRlZCA9IGFsbElkcy5zb3J0KGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgICAgICAgIHJldHVybiBiIC0gYVxuICAgICAgICB9KVxuICAgICAgICBpZiAoc29ydGVkLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgIFRhYmxlRmFjdG9yeS5hZGRSb3coZGIsIHRhYmxlLCBzb3J0ZWRbMF0gKyAxKVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICB9KVxuXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBUYWJsZUZhY3RvcnkuYWRkUm93KGRiLCB0YWJsZSwgMSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0O1xuICAgICAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS5hZGRDb2x1bW4gPSBmdW5jdGlvbihkYiwgdGFibGUpIHtcbiAgICAgICAgdmFyIGNvbE51bXMgPSAkc2NvcGUuY29sdW1ucy5qb2luKCcgJykubWF0Y2goL1xcZCsvZyk7XG4gICAgICAgIGlmIChjb2xOdW1zKSB7XG4gICAgICAgICAgICB2YXIgc29ydGVkTnVtcyA9IGNvbE51bXMuc29ydChmdW5jdGlvbihhLCBiKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGIgLSBhXG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgdmFyIG51bUluTmV3ID0gTnVtYmVyKHNvcnRlZE51bXNbMF0pICsgMTtcbiAgICAgICAgICAgIHZhciBuYW1lTmV3Q29sID0gJ0NvbHVtbiAnICsgbnVtSW5OZXcudG9TdHJpbmcoKTtcblxuICAgICAgICAgICAgVGFibGVGYWN0b3J5LmFkZENvbHVtbihkYiwgdGFibGUsIG5hbWVOZXdDb2wpXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0U2luZ2xlVGFibGUoJHN0YXRlUGFyYW1zLmRiTmFtZSwgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSlcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHRoZVRhYmxlKSB7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHRoZVRhYmxlWzBdO1xuICAgICAgICAgICAgICAgICAgICBDcmVhdGVDb2x1bW5zKCk7XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdmFyIG5leHRDb2xOdW0gPSAkc2NvcGUuY29sdW1ucy5sZW5ndGggKyAxO1xuICAgICAgICAgICAgdmFyIG5ld0NvbE5hbWUgPSAnQ29sdW1uICcgKyBuZXh0Q29sTnVtO1xuICAgICAgICAgICAgVGFibGVGYWN0b3J5LmFkZENvbHVtbihkYiwgdGFibGUsICdDb2x1bW4gMScpXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0U2luZ2xlVGFibGUoJHN0YXRlUGFyYW1zLmRiTmFtZSwgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSlcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHRoZVRhYmxlKSB7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHRoZVRhYmxlWzBdO1xuICAgICAgICAgICAgICAgICAgICBDcmVhdGVDb2x1bW5zKCk7XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICB9XG5cbiAgICB9XG5cbiAgICAvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vT3JnYW5pemluZyBzdHVmZiBpbnRvIGFycmF5cy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgIC8vIEdldCBhbGwgb2YgdGhlIGNvbHVtbnMgdG8gY3JlYXRlIHRoZSBjb2x1bW5zIG9uIHRoZSBib290c3RyYXAgdGFibGVcblxuICAgIGZ1bmN0aW9uIENyZWF0ZUNvbHVtbnMoKSB7XG4gICAgICAgICRzY29wZS5jb2x1bW5zID0gW107XG4gICAgICAgICRzY29wZS5vcmlnaW5hbENvbFZhbHMgPSBbXTtcbiAgICAgICAgdmFyIHRhYmxlID0gJHNjb3BlLnNpbmdsZVRhYmxlWzBdO1xuXG5cbiAgICAgICAgZm9yICh2YXIgcHJvcCBpbiB0YWJsZSkge1xuICAgICAgICAgICAgaWYgKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuY29sdW1ucy5wdXNoKHByb3ApO1xuICAgICAgICAgICAgICAgICRzY29wZS5vcmlnaW5hbENvbFZhbHMucHVzaChwcm9wKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cblxuICAgIENyZWF0ZUNvbHVtbnMoKTtcblxuICAgIGZ1bmN0aW9uIGNyZWF0ZVZpcnR1YWxDb2x1bW5zKCkge1xuICAgICAgICBpZiAoJHNjb3BlLmFzc29jaWF0aW9ucy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAkc2NvcGUudmlydHVhbENvbHVtbnMgPSBbXTtcbiAgICAgICAgICAgICRzY29wZS5hc3NvY2lhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgICAgICBpZiAocm93LlRhYmxlMSA9PT0gJHNjb3BlLnRoZVRhYmxlTmFtZSAmJiByb3cuUmVsYXRpb25zaGlwMSA9PT0gJ2hhc01hbnknKSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciB2aXJ0dWFsID0ge307XG4gICAgICAgICAgICAgICAgICAgIHZpcnR1YWwubmFtZSA9IHJvdy5BbGlhczE7XG4gICAgICAgICAgICAgICAgICAgIGlmIChyb3cuVGhyb3VnaCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC50YWJsZSA9IHJvdy5UaHJvdWdoO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5jb2x1bW5rZXkgPSByb3cuQWxpYXMxO1xuICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC50YWJsZSA9IHJvdy5UYWJsZTI7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLmNvbHVtbmtleSA9IHJvdy5BbGlhczI7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnZpcnR1YWxDb2x1bW5zLnB1c2godmlydHVhbCk7XG4gICAgICAgICAgICAgICAgfSBlbHNlIGlmIChyb3cuVGFibGUyID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmIHJvdy5SZWxhdGlvbnNoaXAyID09PSAnaGFzTWFueScpIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHZpcnR1YWwgPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5uYW1lID0gcm93LkFsaWFzMjtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHJvdy5UaHJvdWdoKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLnRhYmxlID0gcm93LlRocm91Z2g7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLmNvbHVtbmtleSA9IHJvdy5BbGlhczI7XG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLnRhYmxlID0gcm93LlRhYmxlMTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwuY29sdW1ua2V5ID0gcm93LkFsaWFzMTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAkc2NvcGUudmlydHVhbENvbHVtbnMucHVzaCh2aXJ0dWFsKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgY3JlYXRlVmlydHVhbENvbHVtbnMoKTtcblxuICAgIC8vdGhpcyBmdW5jdGlvbiB3aWxsIHJlIHJ1biB3aGVuIHRoZSBmaWx0ZXIgZnVuY3Rpb24gaXMgaW52b2tlZCwgaW4gb3JkZXIgdG8gcmVwb3B1bGF0ZSB0aGUgdGFibGVcbiAgICBmdW5jdGlvbiBDcmVhdGVSb3dzKCkge1xuICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheSA9IFtdO1xuICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIHZhciByb3dWYWx1ZXMgPSBbXTtcbiAgICAgICAgICAgIHZhciByb3dPYmogPSB7fTtcblxuICAgICAgICAgICAgZm9yICh2YXIgcHJvcCBpbiByb3cpIHtcbiAgICAgICAgICAgICAgICBpZiAocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jykgcm93VmFsdWVzLnB1c2goe1xuICAgICAgICAgICAgICAgICAgICBjb2w6IHByb3AsXG4gICAgICAgICAgICAgICAgICAgIHZhbHVlOiByb3dbcHJvcF1cbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcm93T2JqLnZhbHVlcyA9IHJvd1ZhbHVlcztcbiAgICAgICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5LnB1c2gocm93T2JqKTtcbiAgICAgICAgfSlcbiAgICB9XG5cbiAgICAvLyBTb3J0IHRoZSB2YWx1ZXMgaW4gc2luZ2xlVGFibGUgc28gdGhhdCBhbGwgdGhlIHZhbHVlcyBmb3IgYSBnaXZlbiByb3cgYXJlIGdyb3VwZWRcbiAgICBDcmVhdGVSb3dzKCk7XG4gICAgLy9zZW5kcyB0aGUgZmlsdGVyaW5nIHF1ZXJ5IGFuZCB0aGVuIHJlIHJlbmRlcnMgdGhlIHRhYmxlIHdpdGggZmlsdGVyZWQgZGF0YVxuICAgICRzY29wZS5maWx0ZXIgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgZGF0YSkge1xuICAgICAgICBUYWJsZUZhY3RvcnkuZmlsdGVyKGRiTmFtZSwgdGFibGVOYW1lLCBkYXRhKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0LmRhdGE7XG4gICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgfSlcbiAgICB9XG5cblxuICAgICRzY29wZS5jaGVja0ZvcmVpZ24gPSBmdW5jdGlvbihjb2wpIHtcbiAgICAgICAgcmV0dXJuICRzY29wZS5mb3JlaWduQ29scy5oYXNPd25Qcm9wZXJ0eShjb2wpO1xuICAgIH1cblxuICAgICRzY29wZS5maW5kUHJpbWFyeSA9IFRhYmxlRmFjdG9yeS5maW5kUHJpbWFyeTtcblxuICAgIC8vKioqKioqKioqKioqIEltcG9ydGFudCAqKioqKioqKipcbiAgICAvLyBNYWtlIHN1cmUgdG8gdXBkYXRlIHRoZSByb3cgdmFsdWVzIEJFRk9SRSB0aGUgY29sdW1uIG5hbWVcbiAgICAvLyBUaGUgcm93VmFsc1RvVXBkYXRlIGFycmF5IHN0b3JlcyB0aGUgdmFsdWVzIG9mIHRoZSBPUklHSU5BTCBjb2x1bW4gbmFtZXMgc28gaWYgdGhlIGNvbHVtbiBuYW1lIGlzIHVwZGF0ZWQgYWZ0ZXIgdGhlIHJvdyB2YWx1ZSwgd2Ugc3RpbGwgaGF2ZSByZWZlcmVuY2UgdG8gd2hpY2ggY29sdW1uIHRoZSByb3cgdmFsdWUgcmVmZXJlbmNlc1xuXG5cbiAgICAvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vVXBkYXRpbmcgQ29sdW1uIFN0dWZmLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuXG4gICAgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZSA9IFtdO1xuXG4gICAgJHNjb3BlLnVwZGF0ZUNvbHVtbnMgPSBmdW5jdGlvbihvbGQsIG5ld0NvbE5hbWUsIGkpIHtcbiAgICAgICAgJHNjb3BlLmNvbHVtbnNbaV0gPSBuZXdDb2xOYW1lO1xuXG4gICAgICAgIHZhciBjb2xPYmogPSB7IG9sZFZhbDogJHNjb3BlLm9yaWdpbmFsQ29sVmFsc1tpXSwgbmV3VmFsOiBuZXdDb2xOYW1lIH07XG5cbiAgICAgICAgLy8gaWYgdGhlcmUgaXMgbm90aGluZyBpbiB0aGUgYXJyYXkgdG8gdXBkYXRlLCBwdXNoIHRoZSB1cGRhdGUgaW50byBpdFxuICAgICAgICBpZiAoJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZS5sZW5ndGggPT09IDApIHsgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZS5wdXNoKGNvbE9iaik7IH0gZWxzZSB7XG4gICAgICAgICAgICBmb3IgKHZhciBlID0gMDsgZSA8ICRzY29wZS5jb2xWYWxzVG9VcGRhdGUubGVuZ3RoOyBlKyspIHtcbiAgICAgICAgICAgICAgICBpZiAoJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZVtlXS5vbGRWYWwgPT09IGNvbE9iai5vbGRWYWwpIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZVtlXSA9IGNvbE9iajtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgICRzY29wZS5jb2xWYWxzVG9VcGRhdGUucHVzaChjb2xPYmopO1xuICAgICAgICB9XG4gICAgICAgIC8vIGNoZWNrIHRvIHNlZSBpZiB0aGUgcm93IGlzIGFscmVhZHkgc2NoZWR1bGVkIHRvIGJlIHVwZGF0ZWQsIGlmIGl0IGlzLCB0aGVuIHVwZGF0ZSBpdCB3aXRoIHRoZSBuZXcgdGhpbmcgdG8gYmUgdXBkYXRlZFxuICAgIH1cblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9VcGRhdGluZyBSb3cgU3R1ZmYvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG5cbiAgICAkc2NvcGUucm93VmFsc1RvVXBkYXRlID0gW107XG5cbiAgICAkc2NvcGUudXBkYXRlUm93ID0gZnVuY3Rpb24ob2xkLCBuZXdDZWxsLCByb3csIGksIGope1xuICAgICAgICB2YXIgY29scyA9ICRzY29wZS5vcmlnaW5hbENvbFZhbHM7XG4gICAgICAgIHZhciBmb3VuZCA9IGZhbHNlO1xuICAgICAgICB2YXIgY29sTmFtZSA9IGNvbHNbal07XG4gICAgICAgIGZvcih2YXIgayA9IDA7IGsgPCAkc2NvcGUucm93VmFsc1RvVXBkYXRlLmxlbmd0aDsgaysrKXtcbiAgICAgICAgICAgIHZhciBvYmogPSAkc2NvcGUucm93VmFsc1RvVXBkYXRlW2tdO1xuICAgICAgICAgICAgY29uc29sZS5sb2cob2JqKVxuICAgICAgICAgICAgaWYob2JqWydpZCddID09PSBpKXtcbiAgICAgICAgICAgICAgICBmb3VuZCA9IHRydWU7XG4gICAgICAgICAgICAgICAgaWYob2JqW2NvbE5hbWVdKSBvYmpbY29sTmFtZV0gPSBuZXdDZWxsO1xuICAgICAgICAgICAgICAgIG9ialtjb2xOYW1lXSA9IG5ld0NlbGw7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgaWYoIWZvdW5kKSB7XG4gICAgICAgICAgICB2YXIgcm93T2JqID0ge307XG4gICAgICAgICAgICByb3dPYmpbJ2lkJ10gPSBpO1xuICAgICAgICAgICAgcm93T2JqW2NvbE5hbWVdID0gbmV3Q2VsbDtcbiAgICAgICAgICAgICRzY29wZS5yb3dWYWxzVG9VcGRhdGUucHVzaChyb3dPYmopXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAkc2NvcGUudXBkYXRlQmFja2VuZCA9IGZ1bmN0aW9uKCkge1xuICAgICAgICB2YXIgZGF0YSA9IHsgcm93czogJHNjb3BlLnJvd1ZhbHNUb1VwZGF0ZSwgY29sdW1uczogJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZSB9XG4gICAgICAgIFRhYmxlRmFjdG9yeS51cGRhdGVCYWNrZW5kKCRzY29wZS50aGVEYk5hbWUsICRzY29wZS50aGVUYWJsZU5hbWUsIGRhdGEpO1xuICAgIH1cblxuXG4gICAgJHNjb3BlLmRlbGV0ZVRhYmxlID0gZnVuY3Rpb24oKSB7XG4gICAgICAgIFRhYmxlRmFjdG9yeS5kZWxldGVUYWJsZSgkc2NvcGUuY3VycmVudFRhYmxlKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgJHN0YXRlLmdvKCdUYWJsZScsIHsgZGJOYW1lOiAkc2NvcGUudGhlRGJOYW1lIH0sIHsgcmVsb2FkOiB0cnVlIH0pXG4gICAgICAgICAgICB9KVxuICAgIH1cblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9RdWVyeWluZyBTdHVmZi8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMgPSBbXTtcblxuICAgICRzY29wZS50YWJsZXNUb1F1ZXJ5ID0gW107XG5cbiAgICBhc3NvY2lhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgaWYgKHJvdy5UYWJsZTEgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9ucy5pbmRleE9mKHJvdy5UYWJsZTIpID09IC0xKSB7XG4gICAgICAgICAgICAkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zLnB1c2gocm93LlRhYmxlMik7XG4gICAgICAgIH0gZWxzZSBpZiAocm93LlRhYmxlMiA9PT0gJHNjb3BlLnRoZVRhYmxlTmFtZSAmJiAkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zLmluZGV4T2Yocm93LlRhYmxlMSkgPT0gLTEpIHtcbiAgICAgICAgICAgICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMucHVzaChyb3cuVGFibGUxKTtcbiAgICAgICAgfVxuICAgIH0pXG5cbiAgICAkc2NvcGUuZ2V0QXNzb2NpYXRlZCA9IGZ1bmN0aW9uKHZhbCkge1xuICAgICAgICBpZiAoJHNjb3BlLnRhYmxlc1RvUXVlcnkuaW5kZXhPZigkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zW3ZhbF0pID09PSAtMSkge1xuICAgICAgICAgICAgJHNjb3BlLnRhYmxlc1RvUXVlcnkucHVzaCgkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zW3ZhbF0pXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB2YXIgaSA9ICRzY29wZS50YWJsZXNUb1F1ZXJ5LmluZGV4T2YoJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9uc1t2YWxdKTtcbiAgICAgICAgICAgICRzY29wZS50YWJsZXNUb1F1ZXJ5LnNwbGljZShpLCAxKVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLmNvbHVtbnNGb3JRdWVyeSA9IFtdO1xuXG4gICAgJHNjb3BlLmdldENvbHVtbnNGb3JUYWJsZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgICB2YXIgcHJvbWlzZXNGb3JDb2x1bW5zID0gW107XG4gICAgICAgICRzY29wZS50YWJsZXNUb1F1ZXJ5LmZvckVhY2goZnVuY3Rpb24odGFibGVOYW1lKSB7XG4gICAgICAgICAgICByZXR1cm4gcHJvbWlzZXNGb3JDb2x1bW5zLnB1c2goVGFibGVGYWN0b3J5LmdldENvbHVtbnNGb3JUYWJsZSgkc2NvcGUudGhlRGJOYW1lLCB0YWJsZU5hbWUpKVxuICAgICAgICB9KVxuICAgICAgICBQcm9taXNlLmFsbChwcm9taXNlc0ZvckNvbHVtbnMpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihjb2x1bW5zKSB7XG4gICAgICAgICAgICAgICAgY29sdW1ucy5mb3JFYWNoKGZ1bmN0aW9uKGNvbHVtbikge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuY29sdW1uc0ZvclF1ZXJ5LnB1c2goY29sdW1uKTtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLiRldmFsQXN5bmMoKVxuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB9KVxuXG4gICAgfVxuXG4gICAgdmFyIHNlbGVjdGVkQ29sdW1ucyA9IHt9O1xuICAgIHZhciBxdWVyeVRhYmxlO1xuXG4gICAgJHNjb3BlLmdldERhdGFGcm9tQ29sdW1ucyA9IGZ1bmN0aW9uKHZhbCkge1xuICAgICAgICBpZighc2VsZWN0ZWRDb2x1bW5zKSBzZWxlY3RlZENvbHVtbnMgPSBbXTtcblxuICAgICAgICB2YXIgY29sdW1uTmFtZSA9ICRzY29wZS5jb2x1bW5zRm9yUXVlcnlbMF1bJ2NvbHVtbnMnXVt2YWwuaV07XG4gICAgICAgIHZhciB0YWJsZU5hbWUgPSB2YWwudGFibGVOYW1lXG4gICAgICAgIHF1ZXJ5VGFibGUgPSB0YWJsZU5hbWU7XG5cbiAgICAgICAgaWYgKCFzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXSkgc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0gPSBbXTtcbiAgICAgICAgaWYgKHNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdLmluZGV4T2YoY29sdW1uTmFtZSkgIT09IC0xKSB7XG4gICAgICAgICAgICBzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXS5zcGxpY2Uoc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0uaW5kZXhPZihjb2x1bW5OYW1lKSwgMSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdLnB1c2goY29sdW1uTmFtZSk7XG4gICAgICAgIH1cbiAgICAgICAgJHNjb3BlLnNlbGVjdGVkQ29sdW1ucyA9IHNlbGVjdGVkQ29sdW1ucztcbiAgICB9XG5cblxuICAgIC8vIFJ1bm5pbmcgdGhlIHF1ZXJ5ICsgcmVuZGVyaW5nIHRoZSBxdWVyeVxuICAgICRzY29wZS5yZXN1bHRPZlF1ZXJ5ID0gW107XG5cbiAgICAkc2NvcGUucXVlcnlSZXN1bHQ7XG5cbiAgICAkc2NvcGUuYXJyID0gW107XG5cblxuICAgIC8vIHRoZVRhYmxlTmFtZVxuXG4gICAgJHNjb3BlLnJ1bkpvaW4gPSBmdW5jdGlvbigpIHtcbiAgICAgICAgLy8gZGJOYW1lLCB0YWJsZTEsIGFycmF5T2ZUYWJsZXMsIHNlbGVjdGVkQ29sdW1ucywgYXNzb2NpYXRpb25zXG4gICAgICAgIHZhciBjb2x1bW5zVG9SZXR1cm4gPSAkc2NvcGUuY29sdW1ucy5tYXAoZnVuY3Rpb24oY29sTmFtZSl7XG4gICAgICAgICAgICByZXR1cm4gJHNjb3BlLnRoZVRhYmxlTmFtZSArICcuJyArIGNvbE5hbWU7XG4gICAgICAgIH0pXG4gICAgICAgIGZvcih2YXIgcHJvcCBpbiAkc2NvcGUuc2VsZWN0ZWRDb2x1bW5zKXtcbiAgICAgICAgICAgJHNjb3BlLnNlbGVjdGVkQ29sdW1uc1twcm9wXS5mb3JFYWNoKGZ1bmN0aW9uKGNvbCl7XG4gICAgICAgICAgICAgICAgY29sdW1uc1RvUmV0dXJuLnB1c2gocHJvcCArICcuJyArIGNvbClcbiAgICAgICAgICAgfSlcbiAgICAgICAgfVxuICAgICAgICBUYWJsZUZhY3RvcnkucnVuSm9pbigkc2NvcGUudGhlRGJOYW1lLCAkc2NvcGUudGhlVGFibGVOYW1lLCAkc2NvcGUudGFibGVzVG9RdWVyeSwgJHNjb3BlLnNlbGVjdGVkQ29sdW1ucywgJHNjb3BlLmFzc29jaWF0aW9ucywgY29sdW1uc1RvUmV0dXJuKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocXVlcnlSZXN1bHQpIHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmxvZygnUVVFUllSUkVTVUxUJywgcXVlcnlSZXN1bHQpO1xuICAgICAgICAgICAgICAgICRzY29wZS5xdWVyeVJlc3VsdCA9IHF1ZXJ5UmVzdWx0O1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnVGFibGUuU2luZ2xlLnF1ZXJ5Jyk7XG4gICAgICAgICAgICB9KVxuICAgIH1cblxuICAgICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9IHRydWU7XG5cbiAgICAkc2NvcGUub3BlbiA9IGZ1bmN0aW9uIChkYk5hbWUsIHRibE5hbWUsIGNvbCwgaW5kZXgpIHtcblxuICAgICAgdmFyIG1vZGFsSW5zdGFuY2UgPSAkdWliTW9kYWwub3Blbih7XG4gICAgICAgIGFuaW1hdGlvbjogJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL2Fzc29jaWF0aW9uLm1vZGFsLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnQXNzb2NpYXRpb25JbnN0YW5jZUN0cmwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgZm9yZWlnbkNvbHM6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiAkc2NvcGUuZm9yZWlnbkNvbHM7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBmb3JUYWJsZTogZnVuY3Rpb24oVGFibGVGYWN0b3J5KXtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKHRibE5hbWUpXG4gICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmZpbmRQcmltYXJ5KGRiTmFtZSwgdGJsTmFtZSk7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBmb3JUYWJsZU5hbWU6IGZ1bmN0aW9uKCl7XG4gICAgICAgICAgICByZXR1cm4gdGJsTmFtZTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIGN1cnJUYWJsZTogZnVuY3Rpb24oKXtcbiAgICAgICAgICAgIHJldHVybiAkc2NvcGUudGhlVGFibGVOYW1lXG4gICAgICAgICAgfSxcbiAgICAgICAgICBjb2xOYW1lOiBmdW5jdGlvbiAoKXtcbiAgICAgICAgICAgIHJldHVybiBjb2w7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBpZDE6IGZ1bmN0aW9uKCl7XG4gICAgICAgICAgICByZXR1cm4gaW5kZXg7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9KTtcblxuICAgICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKFwiQ0xPU0VEXCIpXG4gICAgICAgICRzY29wZS4kZXZhbEFzeW5jKCk7XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgJHNjb3BlLnRvZ2dsZUFuaW1hdGlvbiA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9ICEkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQ7XG4gICAgfTtcblxufSk7XG4iLCJhcHAuY29udHJvbGxlcignVGFibGVDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgYWxsVGFibGVzLCAkc3RhdGUsIFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zLCAkdWliTW9kYWwsIEhvbWVGYWN0b3J5LCBhc3NvY2lhdGlvbnMsIGFsbENvbHVtbnMpIHtcblxuXHQkc2NvcGUuYWxsVGFibGVzID0gYWxsVGFibGVzO1xuXG5cdCRzY29wZS5jb2x1bW5BcnJheSA9IFtdO1xuXG5cdCRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lXG5cblx0JHNjb3BlLmFzc29jaWF0aW9ucyA9IGFzc29jaWF0aW9ucztcblxuXHQkc2NvcGUuYWxsQ29sdW1ucyA9IGFsbENvbHVtbnM7XG5cblx0JHNjb3BlLmFzc29jaWF0aW9uVGFibGUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lICsgJ19hc3NvYyc7XG5cblx0JHNjb3BlLm51bVRhYmxlcyA9ICRzY29wZS5hbGxUYWJsZXMucm93cy5sZW5ndGg7XG5cblx0JHNjb3BlLmFkZCA9IGZ1bmN0aW9uKCkge1xuXHRcdCRzY29wZS5jb2x1bW5BcnJheS5wdXNoKCcxJyk7XG5cdH1cblxuXHQkc2NvcGUuJHN0YXRlID0gJHN0YXRlOyBcdC8vIHVzZWQgdG8gaGlkZSB0aGUgbGlzdCBvZiBhbGwgdGFibGVzIHdoZW4gaW4gc2luZ2xlIHRhYmxlIHN0YXRlXG5cblx0JHNjb3BlLmFzc29jaWF0aW9uVHlwZXMgPSBbJ2hhc09uZScsICdoYXNNYW55J107XG5cblx0JHNjb3BlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG5cblx0JHNjb3BlLnN1Ym1pdHRlZCA9IGZhbHNlO1xuXG5cdCRzY29wZS5tYWtlQXNzb2NpYXRpb25zID0gZnVuY3Rpb24oYXNzb2NpYXRpb24sIGRiTmFtZSkge1xuXHRcdCRzY29wZS5zdWJtaXR0ZWQgPSB0cnVlO1xuXHRcdFRhYmxlRmFjdG9yeS5tYWtlQXNzb2NpYXRpb25zKGFzc29jaWF0aW9uLCBkYk5hbWUpXG5cdH0gXG5cblx0JHNjb3BlLndoZXJlYmV0d2VlbiA9IGZ1bmN0aW9uKGNvbmRpdGlvbikge1xuXHRcdGlmKGNvbmRpdGlvbiA9PT0gXCJXSEVSRSBCRVRXRUVOXCIgfHwgY29uZGl0aW9uID09PSBcIldIRVJFIE5PVCBCRVRXRUVOXCIpIHJldHVybiB0cnVlO1xuXHR9XG5cblx0JHNjb3BlLmNyZWF0ZVRhYmxlID0gZnVuY3Rpb24odGFibGUpe1xuXHRcdFRhYmxlRmFjdG9yeS5jcmVhdGVUYWJsZSh0YWJsZSlcblx0XHQudGhlbihmdW5jdGlvbigpe1xuXHRcdFx0JHN0YXRlLmdvKCdUYWJsZScsIHtkYk5hbWU6ICRzY29wZS5kYk5hbWV9LCB7cmVsb2FkOiB0cnVlfSk7XG5cdFx0fSlcblx0fVxuXG5cdCRzY29wZS5jb2x1bW5EYXRhVHlwZSA9IGZ1bmN0aW9uKCkge1xuXHRcdCRzY29wZS5hbGxDb2x1bW5zLmZvckVhY2goZnVuY3Rpb24ob2JqKSB7XG5cdFx0XHRpZihvYmoudGFibGVfbmFtZSA9PT0gJHNjb3BlLnF1ZXJ5LnRhYmxlMSAmJiBvYmouY29sdW1uX25hbWUgPT09ICRzY29wZS5xdWVyeS5jb2x1bW4pICRzY29wZS50eXBlID0gb2JqLmRhdGFfdHlwZTtcblx0XHR9KVxuXHR9XG5cblx0JHNjb3BlLnNlbGVjdGVkQXNzb2MgPSB7fTtcblxuXHQkc2NvcGUuc3VibWl0UXVlcnkgPSBUYWJsZUZhY3Rvcnkuc3VibWl0UXVlcnk7XG5cbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ1RhYmxlRmFjdG9yeScsIGZ1bmN0aW9uICgkaHR0cCwgJHN0YXRlUGFyYW1zKSB7XG5cblx0dmFyIFRhYmxlRmFjdG9yeSA9IHt9O1xuXG5cdGZ1bmN0aW9uIHJlc1RvRGF0YShyZXMpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5kYXRhO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRBbGxUYWJsZXMgPSBmdW5jdGlvbihkYk5hbWUpe1xuICAgIFx0cmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lKVxuICAgIFx0LnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldERiTmFtZSA9IGZ1bmN0aW9uKGRiTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvbWFzdGVyZGIvJyArIGRiTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5maWx0ZXIgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgZGF0YSkge1xuICAgICAgICByZXR1cm4gJGh0dHAucHV0KCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnL2ZpbHRlcicsIGRhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LnVwZGF0ZUJhY2tlbmQgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgZGF0YSkge1xuICAgICAgICByZXR1cm4gJGh0dHAucHV0KCdhcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSwgZGF0YSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuYWRkUm93ID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIHJvd051bWJlcikge1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnYXBpL2NsaWVudGRiL2FkZHJvdy8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lLCB7cm93TnVtYmVyOiByb3dOdW1iZXJ9KVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVSb3cgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgcm93SWQpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnLycgKyByb3dJZClcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVDb2x1bW4gPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgY29sdW1uTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSArICcvY29sdW1uLycgKyBjb2x1bW5OYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmFkZENvbHVtbiA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCBudW1OZXdDb2wpe1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnYXBpL2NsaWVudGRiL2FkZGNvbHVtbi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lICsgJy8nICsgbnVtTmV3Q29sKVxuICAgIH1cbiAgICBUYWJsZUZhY3RvcnkuY3JlYXRlVGFibGUgPSBmdW5jdGlvbih0YWJsZSl7XG4gICAgICAgIHRhYmxlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG4gICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL2NsaWVudGRiJywgdGFibGUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmRlbGV0ZVRhYmxlID0gZnVuY3Rpb24oY3VycmVudFRhYmxlKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvY2xpZW50ZGIvJyArIGN1cnJlbnRUYWJsZS5kYk5hbWUgKyAnLycgKyBjdXJyZW50VGFibGUudGFibGVOYW1lKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5tYWtlQXNzb2NpYXRpb25zID0gZnVuY3Rpb24oYXNzb2NpYXRpb24sIGRiTmFtZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy9hc3NvY2lhdGlvbicsIGFzc29jaWF0aW9uKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5kZWxldGVEYiA9IGZ1bmN0aW9uKGRiTmFtZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldEFzc29jaWF0aW9ucyA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvYXNzb2NpYXRpb250YWJsZS8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgICBUYWJsZUZhY3RvcnkuZ2V0QWxsQXNzb2NpYXRpb25zID0gZnVuY3Rpb24oZGJOYW1lKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvYWxsYXNzb2NpYXRpb25zLycgKyBkYk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldEFsbENvbHVtbnMgPSBmdW5jdGlvbihkYk5hbWUpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi9nZXRhbGxjb2x1bW5zLycgKyBkYk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldENvbHVtbnNGb3JUYWJsZSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi9jb2x1bW5zZm9ydGFibGUvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkucnVuSm9pbiA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGUxLCBhcnJheU9mVGFibGVzLCBzZWxlY3RlZENvbHVtbnMsIGFzc29jaWF0aW9ucywgY29sc1RvUmV0dXJuKSB7XG4gICAgICAgIHZhciBkYXRhID0ge307XG4gICAgICAgIGRhdGEuZGJOYW1lID0gZGJOYW1lO1xuICAgICAgICBkYXRhLnRhYmxlMiA9IGFycmF5T2ZUYWJsZXNbMF07XG4gICAgICAgIGRhdGEuYXJyYXlPZlRhYmxlcyA9IGFycmF5T2ZUYWJsZXM7XG4gICAgICAgIGRhdGEuc2VsZWN0ZWRDb2x1bW5zID0gc2VsZWN0ZWRDb2x1bW5zO1xuICAgICAgICBkYXRhLmNvbHNUb1JldHVybiA9IGNvbHNUb1JldHVybjtcblxuICAgICAgICAvLyBbaGFzTWFueSwgaGFzT25lLCBoYXNNYW55IHByaW1hcnkga2V5LCBoYXNPbmUgZm9yZ2VpbiBrZXldXG5cbiAgICAgICAgYXNzb2NpYXRpb25zLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICBpZihyb3cuVGFibGUxID09PSB0YWJsZTEgJiYgcm93LlRhYmxlMiA9PT0gZGF0YS50YWJsZTIpe1xuICAgICAgICAgICAgICAgIGRhdGEuYWxpYXMgPSByb3cuQWxpYXMxO1xuICAgICAgICAgICAgICAgIGlmKHJvdy5SZWxhdGlvbnNoaXAxID09PSAnaGFzT25lJyl7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUxID0gcm93LlRhYmxlMjtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTIgPSByb3cuVGFibGUxO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNle1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMSA9IHJvdy5UYWJsZTE7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUyID0gcm93LlRhYmxlMjsgICBcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIGlmKHJvdy5UYWJsZTEgPT09IGRhdGEudGFibGUyICYmIHJvdy5UYWJsZTIgPT09IHRhYmxlMSl7XG4gICAgICAgICAgICAgICAgZGF0YS5hbGlhcyA9IHJvdy5BbGlhczE7XG4gICAgICAgICAgICAgICAgaWYocm93LlJlbGF0aW9uc2hpcDEgPT09ICdoYXNNYW55Jyl7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUxID0gcm93LlRhYmxlMTtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTIgPSByb3cuVGFibGUyO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNle1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMSA9IHJvdy5UYWJsZTI7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUyID0gcm93LlRhYmxlMTsgICBcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pXG5cbiAgICAgICAgY29uc29sZS5sb2coJ0RBVEEnLGRhdGEpO1xuXG4gICAgICAgIHJldHVybiAkaHR0cC5wdXQoJy9hcGkvY2xpZW50ZGIvcnVuam9pbicsIGRhdGEpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldFByaW1hcnlLZXlzID0gZnVuY3Rpb24oaWQsIGRiTmFtZSwgdGFibGVOYW1lLCBjb2x1bW5rZXkpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnLycgKyBpZCArIFwiL1wiICsgY29sdW1ua2V5KVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5maW5kUHJpbWFyeSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGJsTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvcHJpbWFyeS8nK2RiTmFtZSsnLycrdGJsTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3Rvcnkuc2V0Rm9yZWlnbktleSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGJsTmFtZSwgY29sTmFtZSwgaWQxLCBpZDIpe1xuICAgICAgICB2YXIgZGF0YSA9IHt9O1xuICAgICAgICBkYXRhLmRiTmFtZSA9IGRiTmFtZTtcbiAgICAgICAgZGF0YS50YmxOYW1lID0gdGJsTmFtZTtcbiAgICAgICAgZGF0YS5jb2xOYW1lID0gY29sTmFtZTtcbiAgICAgICAgZGF0YS5pZDEgPSBpZDE7XG4gICAgICAgIGRhdGEuaWQyID0gaWQyO1xuXG4gICAgICAgIHJldHVybiAkaHR0cC5wdXQoJy9hcGkvY2xpZW50ZGIvc2V0Rm9yZWlnbktleScsIGRhdGEpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7ICAgXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LnVwZGF0ZUpvaW5UYWJsZSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCBpZCwgbmV3Um93LCB0YWJsZVRvVXBkYXRlLCBjb2x1bW5OYW1lKSB7XG4gICAgICAgIHZhciBkYXRhID0ge307XG4gICAgICAgIGRhdGEuZGJOYW1lID0gZGJOYW1lO1xuICAgICAgICBkYXRhLnRibE5hbWUgPSB0YWJsZU5hbWU7XG4gICAgICAgIGRhdGEucm93SWQgPSBpZDtcbiAgICAgICAgZGF0YS5uZXdSb3cgPSBuZXdSb3c7XG4gICAgICAgIGRhdGEudGFibGVUb1VwZGF0ZSA9IHRhYmxlVG9VcGRhdGU7XG4gICAgICAgIGRhdGEuY29sdW1uTmFtZSA9IGNvbHVtbk5hbWU7XG4gICAgICAgXG4gICAgICAgcmV0dXJuICRodHRwLnB1dCgnL2FwaS9jbGllbnRkYi91cGRhdGVKb2luVGFibGUnLCBkYXRhKVxuICAgICAgIC50aGVuKHJlc1RvRGF0YSk7ICBcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuaW5jcmVtZW50ID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLnB1dCgnL2FwaS9jbGllbnRkYi8nKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKycvYWRkcm93b25qb2luJylcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cblx0cmV0dXJuIFRhYmxlRmFjdG9yeTsgXG59KSIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlJywge1xuICAgICAgICB1cmw6ICcvOmRiTmFtZScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvdGFibGUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdUYWJsZUN0cmwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgIFx0YWxsVGFibGVzOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0QWxsVGFibGVzKCRzdGF0ZVBhcmFtcy5kYk5hbWUpO1xuICAgICAgICBcdH0sIFxuICAgICAgICAgICAgYXNzb2NpYXRpb25zOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0QWxsQXNzb2NpYXRpb25zKCRzdGF0ZVBhcmFtcy5kYk5hbWUpO1xuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIGFsbENvbHVtbnM6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRBbGxDb2x1bW5zKCRzdGF0ZVBhcmFtcy5kYk5hbWUpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSk7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUuU2luZ2xlJywge1xuICAgICAgICB1cmw6ICcvOnRhYmxlTmFtZScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvc2luZ2xldGFibGUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdTaW5nbGVUYWJsZUN0cmwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgICBzaW5nbGVUYWJsZTogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldFNpbmdsZVRhYmxlKCRzdGF0ZVBhcmFtcy5kYk5hbWUsICRzdGF0ZVBhcmFtcy50YWJsZU5hbWUpO1xuICAgICAgICAgICAgfSwgXG4gICAgICAgICAgICBhc3NvY2lhdGlvbnM6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRBc3NvY2lhdGlvbnMoJHN0YXRlUGFyYW1zLmRiTmFtZSwgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KTtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5Kb2luJywge1xuICAgICAgICB1cmw6ICcvOnRhYmxlTmFtZS86cm93SWQvOmtleS9qb2luJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9qb2luLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnSm9pblRhYmxlQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICAgIGpvaW5UYWJsZTogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldFByaW1hcnlLZXlzKCRzdGF0ZVBhcmFtcy5yb3dJZCwgJHN0YXRlUGFyYW1zLmRiTmFtZSwgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSwgJHN0YXRlUGFyYW1zLmtleSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KTtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5UaHJvdWdoJywge1xuICAgICAgICB1cmw6ICcvOnRhYmxlTmFtZS90aHJvdWdoJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS90aHJvdWdoLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVGhyb3VnaEN0cmwnLCBcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICAgICAgc2luZ2xlVGFibGU6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSgkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pOyAgXG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUuY3JlYXRlJywge1xuICAgICAgICB1cmw6ICcvY3JlYXRldGFibGUnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL2NyZWF0ZXRhYmxlLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVGFibGVDdHJsJ1xuICAgIH0pO1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlLnNldEFzc29jaWF0aW9uJywge1xuICAgICAgICB1cmw6ICcvc2V0YXNzb2NpYXRpb24nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL3NldGFzc29jaWF0aW9uLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVGFibGVDdHJsJ1xuICAgIH0pO1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlLlNpbmdsZS5xdWVyeScsIHtcbiAgICAgICAgdXJsOiAnL3F1ZXJ5cmVzdWx0JyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9xdWVyeS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1F1ZXJ5VGFibGVDdHJsJ1xuICAgIH0pOyAgICAgXG5cblxufSk7IiwiYXBwLmNvbnRyb2xsZXIoJ1Rocm91Z2hDdHJsJywgZnVuY3Rpb24oJHNjb3BlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgYXNzb2NpYXRpb25zLCBzaW5nbGVUYWJsZSwgJHVpYk1vZGFsKSB7XG5cbiAgICAkc2NvcGUuYXNzb2NpYXRpb25zID0gYXNzb2NpYXRpb25zO1xuICAgICRzY29wZS50d29UYWJsZXMgPSBbXTtcbiAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSBzaW5nbGVUYWJsZVswXTtcbiAgICAkc2NvcGUudGhlRGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZTtcbiAgICAkc2NvcGUudGFibGVOYW1lID0gJHN0YXRlUGFyYW1zLnRhYmxlTmFtZTtcblxuICAgIGZ1bmN0aW9uIGdldDJUYWJsZXMoKSB7XG4gICAgICAgICRzY29wZS5hc3NvY2lhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihhc3NvYykge1xuICAgICAgICAgICAgaWYgKGFzc29jWydUaHJvdWdoJ10gPT09ICRzdGF0ZVBhcmFtcy50YWJsZU5hbWUpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUudHdvVGFibGVzLnB1c2goYXNzb2NbJ1RhYmxlMSddKTtcbiAgICAgICAgICAgICAgICAkc2NvcGUudHdvVGFibGVzLnB1c2goYXNzb2NbJ1RhYmxlMiddKTsgLy9oZXJlIC0gY29tZSBiYWNrXG4gICAgICAgICAgICB9XG4gICAgICAgIH0pXG4gICAgfVxuXG4gICAgZ2V0MlRhYmxlcygpO1xuXG4gICAgZnVuY3Rpb24gQ3JlYXRlQ29sdW1ucygpIHtcbiAgICAgICAgJHNjb3BlLmNvbHVtbnMgPSBbXTtcbiAgICAgICAgdmFyIHRhYmxlID0gc2luZ2xlVGFibGVbMF1bMF07XG4gICAgICAgIGZvciAodmFyIHByb3AgaW4gdGFibGUpIHtcbiAgICAgICAgICAgICRzY29wZS5jb2x1bW5zLnB1c2gocHJvcCk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBDcmVhdGVDb2x1bW5zKCk7XG5cblxuICAgIC8vdGhpcyBmdW5jdGlvbiB3aWxsIHJlIHJ1biB3aGVuIHRoZSBmaWx0ZXIgZnVuY3Rpb24gaXMgaW52b2tlZCwgaW4gb3JkZXIgdG8gcmVwb3B1bGF0ZSB0aGUgdGFibGVcbiAgICBmdW5jdGlvbiBDcmVhdGVSb3dzKCkge1xuXG4gICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5ID0gW107XG4gICAgICAgICRzY29wZS5zaW5nbGVUYWJsZS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgdmFyIHJvd1ZhbHVlcyA9IFtdO1xuICAgICAgICAgICAgZm9yICh2YXIgcHJvcCBpbiByb3cpIHtcbiAgICAgICAgICAgICAgICByb3dWYWx1ZXMucHVzaChyb3dbcHJvcF0pXG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheS5wdXNoKHJvd1ZhbHVlcylcbiAgICAgICAgfSlcbiAgICB9XG5cbiAgICAvLyBTb3J0IHRoZSB2YWx1ZXMgaW4gc2luZ2xlVGFibGUgc28gdGhhdCBhbGwgdGhlIHZhbHVlcyBmb3IgYSBnaXZlbiByb3cgYXJlIGdyb3VwZWRcbiAgICBDcmVhdGVSb3dzKCk7XG5cbiAgICAvLyAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQgPSB0cnVlO1xuXG4gICAgJHNjb3BlLm9wZW4gPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgaW5kZXgsIHJvdywgY29sdW1uTmFtZSkge1xuICAgICAgICBjb25zb2xlLmxvZyhkYk5hbWUsIHRhYmxlTmFtZSwgaW5kZXgsIHJvdywgY29sdW1uTmFtZSk7XG4gICAgICAgIHZhciB0aGVUYWJsZSA9ICRzY29wZS50d29UYWJsZXNbaW5kZXgtMV07XG4gICAgICAgIGNvbnNvbGUubG9nKCd0d29UYWJsZXMnLCAkc2NvcGUudHdvVGFibGVzKTtcbiAgICAgICAgY29uc29sZS5sb2coJ3RoZVRhYmxlJywgdGhlVGFibGUpO1xuXG4gICAgICAgIHZhciBtb2RhbEluc3RhbmNlID0gJHVpYk1vZGFsLm9wZW4oe1xuICAgICAgICAgICAgYW5pbWF0aW9uOiAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQsXG4gICAgICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL3Rocm91Z2gubW9kYWwuaHRtbCcsXG4gICAgICAgICAgICBjb250cm9sbGVyOiAnVGhyb3VnaE1vZGFsQ3RybCcsXG4gICAgICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgICAgICAgdGhlVGFibGU6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldFNpbmdsZVRhYmxlKGRiTmFtZSwgdGhlVGFibGUpO1xuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgdGFibGVOYW1lIDogZnVuY3Rpb24oKSB7IHJldHVybiB0aGVUYWJsZSB9LFxuICAgICAgICAgICAgICAgIHJvd0lkIDogZnVuY3Rpb24oKSB7IHJldHVybiByb3cgfSxcbiAgICAgICAgICAgICAgICBjb2x1bW5OYW1lIDogZnVuY3Rpb24oKSB7IHJldHVybiBjb2x1bW5OYW1lIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG5cbiAgICAgICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiQ0xPU0VEXCIpXG4gICAgICAgICAgICAkc2NvcGUuJGV2YWxBc3luYygpO1xuICAgICAgICB9KTtcbiAgICB9O1xuXG4gICAgJHNjb3BlLnRvZ2dsZUFuaW1hdGlvbiA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQgPSAhJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkO1xuICAgIH07XG5cbiAgICAkc2NvcGUubmV3Um93ID0gZnVuY3Rpb24oZGIsIHRhYmxlKSB7XG4gICAgICAgVGFibGVGYWN0b3J5LmluY3JlbWVudChkYiwgdGFibGUpXG4gICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgIGNvbnNvbGUubG9nKHJlc3VsdCk7XG4gICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5ID0gcmVzdWx0O1xuICAgICAgICAkc2NvcGUuJGV2YWxBc3luYygpO1xuICAgICAgIH0pXG4gICAgfVxuXG4gICAgLy9kZWxldGUgYSByb3cgXG4gICAgJHNjb3BlLnNob3dEZWxldGUgPSBmYWxzZTtcbiAgICAkc2NvcGUudG9nZ2xlRGVsZXRlID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICRzY29wZS5zaG93RGVsZXRlID0gISRzY29wZS5zaG93RGVsZXRlXG4gICAgfVxuXG4gICAgJHNjb3BlLmRlbGV0ZVNlbGVjdGVkID0gZnVuY3Rpb24oZGIsIHRhYmxlLCBpbnN0YW5jZUFycmF5KSB7XG4gICAgICAgIGluc3RhbmNlQXJyYXkuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIGlmIChyb3cuc2VsZWN0ZWQpIHtcbiAgICAgICAgICAgICAgICBUYWJsZUZhY3RvcnkucmVtb3ZlUm93KGRiLCB0YWJsZSwgcm93WzBdKVxuICAgICAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHJlc3VsdDtcbiAgICAgICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSlcbiAgICAgICAgJHNjb3BlLnNob3dEZWxldGUgPSBmYWxzZTtcbiAgICB9XG5cbiAgICAkc2NvcGUuc2VsZWN0QWxsID0gZnVuY3Rpb24oaW5zdGFuY2VBcnJheSkge1xuICAgICAgICBpZiAoJHNjb3BlLnNlbGVjdGVkQWxsKSB7XG4gICAgICAgICAgICBpbnN0YW5jZUFycmF5LmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICAgICAgcm93LnNlbGVjdGVkID0gdHJ1ZTtcbiAgICAgICAgICAgIH0pXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBpbnN0YW5jZUFycmF5LmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICAgICAgcm93LnNlbGVjdGVkID0gZmFsc2U7XG4gICAgICAgICAgICB9KVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLnVuY2hlY2tTZWxlY3RBbGwgPSBmdW5jdGlvbihpbnN0YW5jZUFycmF5KSB7XG4gICAgICAgIGlmICgkc2NvcGUuc2VsZWN0ZWRBbGwgPT09IHRydWUpIHtcbiAgICAgICAgICAgICRzY29wZS5zZWxlY3RlZEFsbCA9IGZhbHNlO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLnJlbW92ZVJvdyA9IGZ1bmN0aW9uKGRiLCB0YWJsZSwgcm93KSB7XG4gICAgICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVSb3coZGIsIHRhYmxlLCByb3cpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgfSlcbiAgICB9XG5cbn0pXG4iLCJhcHAuY29udHJvbGxlcignVGhyb3VnaE1vZGFsQ3RybCcsIGZ1bmN0aW9uKCRzY29wZSwgJHVpYk1vZGFsSW5zdGFuY2UsIFRhYmxlRmFjdG9yeSwgSG9tZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgJHN0YXRlLCB0aGVUYWJsZSwgdGFibGVOYW1lLCByb3dJZCwgY29sdW1uTmFtZSkge1xuXG4gICAgJHNjb3BlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG5cbiAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSB0aGVUYWJsZTtcblxuICAgICRzY29wZS50YWJsZU5hbWUgPSB0YWJsZU5hbWU7XG5cbiAgICAkc2NvcGUucm93SWQgPSByb3dJZDtcblxuICAgICRzY29wZS5jb2x1bW5OYW1lID0gY29sdW1uTmFtZTtcblxuICAgICRzY29wZS5zZXRTZWxlY3RlZCA9IGZ1bmN0aW9uKCkge1xuXG4gICAgICAgICRzY29wZS5jdXJyUm93ID0gdGhpcy5yb3c7XG4gICAgICAgIC8vIGNvbnNvbGUubG9nKCdIRVJFJywgJHNjb3BlLmN1cnJSb3cpO1xuICAgIH1cblxuXG4gICAgLy8gY29uc29sZS5sb2coJHNjb3BlLnNpbmdsZVRhYmxlWzBdKVxuICAgIGZ1bmN0aW9uIENyZWF0ZUNvbHVtbnMoKSB7XG4gICAgICAgICRzY29wZS5jb2x1bW5zID0gW107XG4gICAgICAgIHZhciB0YWJsZSA9ICRzY29wZS5zaW5nbGVUYWJsZVswXVswXTtcblxuXG4gICAgICAgIGZvciAodmFyIHByb3AgaW4gdGFibGUpIHtcbiAgICAgICAgICAgIGlmIChwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLmNvbHVtbnMucHVzaChwcm9wKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cblxuICAgIENyZWF0ZUNvbHVtbnMoKTtcblxuICAgIC8vdGhpcyBmdW5jdGlvbiB3aWxsIHJlIHJ1biB3aGVuIHRoZSBmaWx0ZXIgZnVuY3Rpb24gaXMgaW52b2tlZCwgaW4gb3JkZXIgdG8gcmVwb3B1bGF0ZSB0aGUgdGFibGVcbiAgICBmdW5jdGlvbiBDcmVhdGVSb3dzKCkge1xuICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheSA9IFtdO1xuICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGVbMF0uZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIHZhciByb3dWYWx1ZXMgPSBbXTtcbiAgICAgICAgICAgIGZvciAodmFyIHByb3AgaW4gcm93KSB7XG4gICAgICAgICAgICAgICAgaWYgKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpIHJvd1ZhbHVlcy5wdXNoKHJvd1twcm9wXSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5LnB1c2gocm93VmFsdWVzKVxuICAgICAgICB9KVxuICAgIH1cblxuICAgIC8vIFNvcnQgdGhlIHZhbHVlcyBpbiBzaW5nbGVUYWJsZSBzbyB0aGF0IGFsbCB0aGUgdmFsdWVzIGZvciBhIGdpdmVuIHJvdyBhcmUgZ3JvdXBlZFxuICAgIENyZWF0ZVJvd3MoKTtcblxuXG4gICAgJHNjb3BlLnNldEZvcmVpZ25LZXkgPSBmdW5jdGlvbihkYk5hbWUsIHRibE5hbWUsIHJvd0lkLCBuZXdSb3cpIHtcbiAgICAgICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoKTtcbiAgICAgICAgY29uc29sZS5sb2coJ0hFUkUnLCAkc2NvcGUuY29sdW1uTmFtZSk7XG4gICAgICAgIGNvbnNvbGUubG9nKGRiTmFtZSwgdGJsTmFtZSwgcm93SWQsIG5ld1JvdywgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSlcbiAgICAgICAgVGFibGVGYWN0b3J5LnVwZGF0ZUpvaW5UYWJsZShkYk5hbWUsIHRibE5hbWUsIHJvd0lkLCBuZXdSb3csICRzdGF0ZVBhcmFtcy50YWJsZU5hbWUsICRzY29wZS5jb2x1bW5OYW1lKTtcbiAgICAgICAgICAgIC8vIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgLy8gICAgIC8vICRzdGF0ZS5nbygnVGFibGUuU2luZ2xlJywgeyBkYk5hbWU6ICRzY29wZS5kYk5hbWUsIHRhYmxlTmFtZTogJHNjb3BlLnNpbmdsZVRhYmxlIH0sIHsgcmVsb2FkOiB0cnVlIH0pXG4gICAgICAgICAgICAvLyB9KVxuICAgIH1cblxuXG5cbiAgICAkc2NvcGUub2sgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoJHNjb3BlLnNlbGVjdGVkLml0ZW0pO1xuICAgIH07XG5cbiAgICAkc2NvcGUuY2FuY2VsID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICR1aWJNb2RhbEluc3RhbmNlLmRpc21pc3MoJ2NhbmNlbCcpO1xuICAgIH07XG59KTtcbiIsImFwcC5mYWN0b3J5KCdGdWxsc3RhY2tQaWNzJywgZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiBbXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQjdnQlh1bENBQUFYUWNFLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL2ZiY2RuLXNwaG90b3MtYy1hLmFrYW1haWhkLm5ldC9ocGhvdG9zLWFrLXhhcDEvdDMxLjAtOC8xMDg2MjQ1MV8xMDIwNTYyMjk5MDM1OTI0MV84MDI3MTY4ODQzMzEyODQxMTM3X28uanBnJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CLUxLVXNoSWdBRXk5U0suanBnJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CNzktWDdvQ01BQWt3N3kuanBnJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CLVVqOUNPSUlBSUZBaDAuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CNnlJeUZpQ0VBQXFsMTIuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DRS1UNzVsV0FBQW1xcUouanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DRXZaQWctVkFBQWs5MzIuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DRWdOTWVPWElBSWZEaEsuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DRVF5SUROV2dBQXU2MEIuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DQ0YzVDVRVzhBRTJsR0ouanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DQWVWdzVTV29BQUFMc2ouanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DQWFKSVA3VWtBQWxJR3MuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DQVFPdzlsV0VBQVk5RmwuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CLU9RYlZyQ01BQU53SU0uanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9COWJfZXJ3Q1lBQXdSY0oucG5nOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CNVBUZHZuQ2NBRUFsNHguanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CNHF3QzBpQ1lBQWxQR2guanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CMmIzM3ZSSVVBQTlvMUQuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9Cd3BJd3IxSVVBQXZPMl8uanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9Cc1NzZUFOQ1lBRU9oTHcuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DSjR2TGZ1VXdBQWRhNEwuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DSTd3empFVkVBQU9QcFMuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DSWRIdlQyVXNBQW5uSFYuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DR0NpUF9ZV1lBQW83NVYuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DSVM0SlBJV0lBSTM3cXUuanBnOmxhcmdlJ1xuICAgIF07XG59KTtcbiIsImFwcC5mYWN0b3J5KCdSYW5kb21HcmVldGluZ3MnLCBmdW5jdGlvbiAoKSB7XG5cbiAgICB2YXIgZ2V0UmFuZG9tRnJvbUFycmF5ID0gZnVuY3Rpb24gKGFycikge1xuICAgICAgICByZXR1cm4gYXJyW01hdGguZmxvb3IoTWF0aC5yYW5kb20oKSAqIGFyci5sZW5ndGgpXTtcbiAgICB9O1xuXG4gICAgdmFyIGdyZWV0aW5ncyA9IFtcbiAgICAgICAgJ0hlbGxvLCB3b3JsZCEnLFxuICAgICAgICAnQXQgbG9uZyBsYXN0LCBJIGxpdmUhJyxcbiAgICAgICAgJ0hlbGxvLCBzaW1wbGUgaHVtYW4uJyxcbiAgICAgICAgJ1doYXQgYSBiZWF1dGlmdWwgZGF5IScsXG4gICAgICAgICdJXFwnbSBsaWtlIGFueSBvdGhlciBwcm9qZWN0LCBleGNlcHQgdGhhdCBJIGFtIHlvdXJzLiA6KScsXG4gICAgICAgICdUaGlzIGVtcHR5IHN0cmluZyBpcyBmb3IgTGluZHNheSBMZXZpbmUuJyxcbiAgICAgICAgJ+OBk+OCk+OBq+OBoeOBr+OAgeODpuODvOOCtuODvOanmOOAgicsXG4gICAgICAgICdXZWxjb21lLiBUby4gV0VCU0lURS4nLFxuICAgICAgICAnOkQnLFxuICAgICAgICAnWWVzLCBJIHRoaW5rIHdlXFwndmUgbWV0IGJlZm9yZS4nLFxuICAgICAgICAnR2ltbWUgMyBtaW5zLi4uIEkganVzdCBncmFiYmVkIHRoaXMgcmVhbGx5IGRvcGUgZnJpdHRhdGEnLFxuICAgICAgICAnSWYgQ29vcGVyIGNvdWxkIG9mZmVyIG9ubHkgb25lIHBpZWNlIG9mIGFkdmljZSwgaXQgd291bGQgYmUgdG8gbmV2U1FVSVJSRUwhJyxcbiAgICBdO1xuXG4gICAgcmV0dXJuIHtcbiAgICAgICAgZ3JlZXRpbmdzOiBncmVldGluZ3MsXG4gICAgICAgIGdldFJhbmRvbUdyZWV0aW5nOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gZ2V0UmFuZG9tRnJvbUFycmF5KGdyZWV0aW5ncyk7XG4gICAgICAgIH1cbiAgICB9O1xuXG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ2Z1bGxzdGFja0xvZ28nLCBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIHtcbiAgICAgICAgcmVzdHJpY3Q6ICdFJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9mdWxsc3RhY2stbG9nby9mdWxsc3RhY2stbG9nby5odG1sJ1xuICAgIH07XG59KTsiLCJhcHAuZGlyZWN0aXZlKCdzaWRlYmFyJywgZnVuY3Rpb24gKCRyb290U2NvcGUsIEF1dGhTZXJ2aWNlLCBBVVRIX0VWRU5UUywgJHN0YXRlKSB7XG5cbiAgICByZXR1cm4ge1xuICAgICAgICByZXN0cmljdDogJ0UnLFxuICAgICAgICBzY29wZToge30sXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvY29tbW9uL2RpcmVjdGl2ZXMvbmF2YmFyL25hdmJhci5odG1sJyxcbiAgICAgICAgbGluazogZnVuY3Rpb24gKHNjb3BlKSB7XG5cbiAgICAgICAgICAgIHNjb3BlLml0ZW1zID0gW1xuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdIb21lJywgc3RhdGU6ICdob21lJyB9LFxuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdBYm91dCcsIHN0YXRlOiAnYWJvdXQnIH0sXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ0RvY3VtZW50YXRpb24nLCBzdGF0ZTogJ2RvY3MnIH0sXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ01lbWJlcnMgT25seScsIHN0YXRlOiAnbWVtYmVyc09ubHknLCBhdXRoOiB0cnVlIH1cbiAgICAgICAgICAgIF07XG5cbiAgICAgICAgICAgIHNjb3BlLnVzZXIgPSBudWxsO1xuXG4gICAgICAgICAgICBzY29wZS5pc0xvZ2dlZEluID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBBdXRoU2VydmljZS5pc0F1dGhlbnRpY2F0ZWQoKTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHNjb3BlLmxvZ291dCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBBdXRoU2VydmljZS5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAkc3RhdGUuZ28oJ2xhbmRpbmdQYWdlJyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICB2YXIgc2V0VXNlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKS50aGVuKGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgICAgICAgICAgIHNjb3BlLnVzZXIgPSB1c2VyO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgdmFyIHJlbW92ZVVzZXIgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgc2NvcGUudXNlciA9IG51bGw7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICBzZXRVc2VyKCk7XG5cbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLmxvZ2luU3VjY2Vzcywgc2V0VXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5sb2dvdXRTdWNjZXNzLCByZW1vdmVVc2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LCByZW1vdmVVc2VyKTtcblxuICAgICAgICB9XG5cbiAgICB9O1xuXG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ3JhbmRvR3JlZXRpbmcnLCBmdW5jdGlvbiAoUmFuZG9tR3JlZXRpbmdzKSB7XG5cbiAgICByZXR1cm4ge1xuICAgICAgICByZXN0cmljdDogJ0UnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL3JhbmRvLWdyZWV0aW5nL3JhbmRvLWdyZWV0aW5nLmh0bWwnLFxuICAgICAgICBsaW5rOiBmdW5jdGlvbiAoc2NvcGUpIHtcbiAgICAgICAgICAgIHNjb3BlLmdyZWV0aW5nID0gUmFuZG9tR3JlZXRpbmdzLmdldFJhbmRvbUdyZWV0aW5nKCk7XG4gICAgICAgIH1cbiAgICB9O1xuXG59KTsiXSwic291cmNlUm9vdCI6Ii9zb3VyY2UvIn0=
