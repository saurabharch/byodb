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

    if ($scope.associations[0]['Through'] === $stateParams.tableName) {
        console.log('HELLO');
        $state.go('Table.Through', { dbName: $stateParams.dbName, tableName: $stateParams.tableName });
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
                $scope.twoTables.push(assoc['Table2']);
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

    $scope.open = function (dbName, tableName, index) {
        var _theTable = $scope.twoTables[index];

        var modalInstance = $uibModal.open({
            animation: $scope.animationsEnabled,
            templateUrl: 'js/table/through.modal.html',
            controller: 'ThroughModalCtrl',
            resolve: {
                theTable: function theTable(TableFactory) {
                    return TableFactory.getSingleTable(dbName, _theTable);
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

app.controller('ThroughModalCtrl', function ($scope, $uibModalInstance, TableFactory, HomeFactory, $stateParams, $state, theTable) {

    $scope.dbName = $stateParams.dbName;

    $scope.singleTable = theTable;

    $scope.setSelected = function () {

        $scope.currRow = this.row;
        console.log($scope.currRow);
    };

    function CreateColumns() {
        $scope.columns = [];
        var table = $scope.singleTable[0];

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

    $scope.setForeignKey = function (dbName, tblName, colName, id1, id2) {
        $uibModalInstance.close();
        TableFactory.setForeignKey(dbName, tblName, colName, id1, id2).then(function () {
            $state.go('Table.Single', { dbName: $scope.dbName, tableName: $scope.singleTable }, { reload: true });
        });
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcC5qcyIsImFib3V0L2Fib3V0LmpzIiwiZG9jcy9kb2NzLmpzIiwiZnNhL2ZzYS1wcmUtYnVpbHQuanMiLCJjcmVhdGVkYi9jcmVhdGVEQi5jb250cm9sbGVyLmpzIiwiY3JlYXRlZGIvY3JlYXRlREIuZmFjdG9yeS5qcyIsImNyZWF0ZWRiL2NyZWF0ZURCLnN0YXRlLmpzIiwiaG9tZS9ob21lLmNvbnRyb2xsZXIuanMiLCJob21lL2hvbWUuZmFjdG9yeS5qcyIsImhvbWUvaG9tZS5zdGF0ZS5qcyIsImxhbmRpbmdQYWdlL2xhbmRpbmdQYWdlLnN0YXRlLmpzIiwib2F1dGgvb2F1dGgtYnV0dG9uLmRpcmVjdGl2ZS5qcyIsImxvZ2luL2xvZ2luLmpzIiwibWVtYmVycy1vbmx5L21lbWJlcnMtb25seS5qcyIsInNpZ251cC9zaWdudXAuanMiLCJ0YWJsZS9hc3NvY2lhdGlvbi5jb250cm9sbGVyLmpzIiwidGFibGUvZGVsZXRlREJNb2RhbC5qcyIsInRhYmxlL2RlbGV0ZVRhYmxlTW9kYWwuanMiLCJ0YWJsZS9qb2luLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS9xdWVyeS5jb250cm9sbGVyLmpzIiwidGFibGUvc2luZ2xldGFibGUuY29udHJvbGxlci5qcyIsInRhYmxlL3RhYmxlLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS90YWJsZS5mYWN0b3J5LmpzIiwidGFibGUvdGFibGUuc3RhdGUuanMiLCJ0YWJsZS90aHJvdWdoLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS90aHJvdWdoTW9kYWwuY29udHJvbGxlci5qcyIsImNvbW1vbi9mYWN0b3JpZXMvRnVsbHN0YWNrUGljcy5qcyIsImNvbW1vbi9mYWN0b3JpZXMvUmFuZG9tR3JlZXRpbmdzLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvZnVsbHN0YWNrLWxvZ28vZnVsbHN0YWNrLWxvZ28uanMiLCJjb21tb24vZGlyZWN0aXZlcy9uYXZiYXIvbmF2YmFyLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvcmFuZG8tZ3JlZXRp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LGlCQUFBLFlBQUE7QUFKQSxTQUFBO0FBTUEsZUFBQTtBQUNBLDJCQUFBLHVCQUFBLFFBQUEsRUFBQTtBQUNBLDJCQUFBLFVBQUEsQ0FBQSxXQUFBLFNBQUEsTUFBQSxDQUFBLEVBQUEsUUFBQTtBQUNBLHVCQUFBLEdBQUEsTUFBQSxDQUFBLFFBQUEsQ0FBQTtBQUNBO0FBSkEsU0FBQTtBQU1BLEtBYkE7O0FBZUEsUUFBQSxNQUFBLENBQUEsVUFBQSxhQUFBLEVBQUE7QUFDQSxzQkFBQSxZQUFBLENBQUEsSUFBQSxDQUFBLENBQ0EsV0FEQSxFQUVBLFVBQUEsU0FBQSxFQUFBO0FBQ0EsbUJBQUEsVUFBQSxHQUFBLENBQUEsaUJBQUEsQ0FBQTtBQUNBLFNBSkEsQ0FBQTtBQU1BLEtBUEE7O0FBU0EsUUFBQSxPQUFBLENBQUEsYUFBQSxFQUFBLFVBQUEsS0FBQSxFQUFBLE9BQUEsRUFBQSxVQUFBLEVBQUEsV0FBQSxFQUFBLEVBQUEsRUFBQTs7QUFFQSxpQkFBQSxpQkFBQSxDQUFBLFFBQUEsRUFBQTtBQUNBLGdCQUFBLE9BQUEsU0FBQSxJQUFBO0FBQ0Esb0JBQUEsTUFBQSxDQUFBLEtBQUEsRUFBQSxFQUFBLEtBQUEsSUFBQTtBQUNBLHVCQUFBLFVBQUEsQ0FBQSxZQUFBLFlBQUE7QUFDQSxtQkFBQSxLQUFBLElBQUE7QUFDQTs7OztBQUlBLGFBQUEsZUFBQSxHQUFBLFlBQUE7QUFDQSxtQkFBQSxDQUFBLENBQUEsUUFBQSxJQUFBO0FBQ0EsU0FGQTs7QUFJQSxhQUFBLGVBQUEsR0FBQSxVQUFBLFVBQUEsRUFBQTs7Ozs7Ozs7OztBQVVBLGdCQUFBLEtBQUEsZUFBQSxNQUFBLGVBQUEsSUFBQSxFQUFBO0FBQ0EsdUJBQUEsR0FBQSxJQUFBLENBQUEsUUFBQSxJQUFBLENBQUE7QUFDQTs7Ozs7QUFLQSxtQkFBQSxNQUFBLEdBQUEsQ0FBQSxVQUFBLEVBQUEsSUFBQSxDQUFBLGlCQUFBLEVBQUEsS0FBQSxDQUFBLFlBQUE7QUFDQSx1QkFBQSxJQUFBO0FBQ0EsYUFGQSxDQUFBO0FBSUEsU0FyQkE7O0FB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LFdBQUEsR0FBQSxVQUFBLEtBQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxjQUFBLE1BQUEsR0FBQSxVQUFBLE1BQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxDQUFBLGVBQUEsRUFBQSxLQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSkE7O0FBTUEsV0FBQSxlQUFBO0FBQ0EsQ0FwQkE7O0FDQUEsSUFBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxtQkFBQSxLQUFBLENBQUEsVUFBQSxFQUFBO0FBQ0EsYUFBQSxXQURBO0FBRUEscUJBQUEsMkJBRkE7QUFHQSxvQkFBQSxjQUhBO0FBSUEsaUJBQUE7QUFDQSwwQkFBQSxzQkFBQSxXQUFBLEVBQUE7QUFDQSx1QkFBQSxZQUFBLGVBQUEsRUFBQTtBQUNBO0FBSEE7QUFKQSxLQUFBO0FBV0EsQ0FaQTtBQ0FBLElBQUEsVUFBQSxDQUFBLFVBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBOztBQUVBLFdBQUEsTUFBQSxHQUFBLE1BQUE7QUFDQSxDQUhBOztBQ0FBLElBQUEsT0FBQSxDQUFBLGFBQUEsRUFBQSxVQUFBLEtBQUEsRUFBQTs7QUFFQSxRQUFBLGNBQUEsRUFBQTs7QUFFQSxhQUFBLFNBQUEsQ0FBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLElBQUEsSUFBQTtBQUNBOztBQUVBLGdCQUFBLFNBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxlQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsZ0JBQUEsUUFBQSxHQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLE1BQUEsQ0FBQSxtQkFBQSxJQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsV0FBQSxXQUFBO0FBQ0EsQ0FuQkE7QUNBQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLG1CQUFBLEtBQUEsQ0FBQSxNQUFBLEVBQUE7QUFDQSxh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QSxTQUZBLEVBRUEsS0FGQSxDQUVBLFlBQUE7QUFDQSxtQkFBQSxLQUFBLEdBQUEsOENBQUE7QUFDQSxTQUpBO0FBTUEsS0FSQTtBQVVBLENBZkE7O0FDVkEsSUFBQSxVQUFBLENBQUEseUJBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxpQkFBQSxFQUFBLFdBQUEsRUFBQSxZQUFBLEVBQUEsV0FBQSxFQUFBLFlBQUEsRUFBQSxNQUFBLEVBQUEsUUFBQSxFQUFBLFlBQUEsRUFBQSxTQUFBLEVBQUEsT0FBQSxFQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxhQUFBLE1BQUE7O0FBRUEsV0FBQSxXQUFBLEdBQUEsUUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxZQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLFNBQUE7O0FBRUEsV0FBQSxPQUFBLEdBQUEsT0FBQTs7QUFFQSxXQUFBLEdBQUEsR0FBQSxHQUFBOztBQUVBLFdBQUEsV0FBQSxHQUFBLFlBQUE7O0FBRUEsZUFBQSxPQUFBLEdBQUEsS0FBQSxHQUFBO0FBQ0EsZ0JBQUEsR0FBQSxDQUFBLE9BQUEsT0FBQTtBQUNBLEtBSkE7O0FBUUEsYUFBQSxhQUFBLEdBQUE7QUFDQSxlQUFBLE9BQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxRQUFBLFNBQUEsQ0FBQSxDQUFBOztBQUdBLGFBQUEsSUFBQSxJQUFBLElBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxPQUFBLENBQUEsSUFBQSxDQUFBLElBQUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7OztBQUlBLGFBQUEsVUFBQSxHQUFBO0FBQ0EsZUFBQSxhQUFBLEdBQUEsRUFBQTtBQUNBLGlCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLFlBQUEsRUFBQTtBQUNBLGlCQUFBLElBQUEsSUFBQSxJQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBLFVBQUEsSUFB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QSxPQUFBLFNBQUEsQ0FBQSxDQUFBLENBQUE7O0FBR0EsYUFBQSxJQUFBLElBQUEsSUFBQSxLQUFBLEVBQUE7QUFDQSxnQkFBQSxTQUFBLFlBQUEsSUFBQSxTQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsSUFBQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTs7O0FBSUEsYUFBQSxVQUFBLEdBQUE7QUFDQSxZQUFBLEtBQUE7QUFDQSxlQUFBLGFBQUEsR0FBQSxFQUFBO0FBQ0Esa0JBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsWUFBQSxFQUFBO0FBQ0EsaUJBQUEsSUFBQSxJQUFBLElBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUEsVUFBQSxJQUFBLENBQUEsSUFBQSxJQUFBLENBQUE7QUFDQTtBQUNBLG1CQUFBLGFBQUEsQ0FBQSxJQUFBLENBQUEsU0FBQTtBQUNBLFNBTkE7QUFPQTs7O0FBR0E7QUFHQSxDQXJDQTtBQ0FBLElBQUEsVUFBQSxDQUFBLGdCQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQTs7QUFFQSxXQUFBLE9BQUEsR0FBQSxVQUFBLGVBQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLENBQUEsZUFBQSxFQUFBLE9BQUEsSUFBQSxDQUFBLEtBQ0E7QUFDQSxpQkFBQSxJQUFBLElBQUEsSUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxVQUFBLElBQUEsSUFBQSxFQUFBLFFBQUEsR0FBQSxXQUFBLEVBQUE7QUFDQSxvQkFBQSxZQUFBLGdCQUFBLFFBQUEsR0FBQSxXQUFBLEVBQUE7QUFDQSx3QkFBQSxHQUFBLENBQUEsT0FBQSxFQUFBLFNBQUEsRUFBQSxRQUFBLE9BQUEsQ0FBQSxTQUFBLE1BQUEsQ0FBQSxDQUFBO0FBQ0Esb0JBQUEsUUFBQSxPQUFBLENBQUEsU0FBQSxNQUFBLENBQUEsQ0FBQSxFQUFBLE9BQUEsSUFBQTtBQUNBO0FBQ0E7QUFDQSxlQUFBLEtBQUE7QUFDQSxLQVhBO0FBYUEsQ0FmQTtBQ0FBLElBQUEsVUFBQSxDQUFBLGlCQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQSxXQUFBLEVBQUEsT0FBQSxFQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsWUFBQSxFQUFBLElBQUEsRUFBQTs7OztBQUlBLFdBQUEsU0FBQSxHQUFBLGFBQUEsTUFBQTtBQUNBLFdBQUEsWUFBQSxHQUFBLGFBQUEsU0FBQTtBQUNBLFdBQUEsV0FBQSxHQUFBLFlBQUEsQ0FBQSxDQUFBO0FBQ0EsV0FBQSxXQUFBLEdBQUEsS0FBQTtBQUNBLFdBQUEsWUFBQSxHQUFBLFlBQUE7O0FBRUEsUUFBQSxPQUFBLFlBQUEsQ0FBQSxDQUFBLEVBQUEsU0FBQSxNQUFBLGFBQUEsU0FBQSxFQUFBO0FBQ0EsZ0JBQUEsR0FBQSxDQUFBLE9BQUE7QUFDQSxlQUFBLEVBQUEsQ0FBQSxlQUFBLEVBQUEsRUFBQSxRQUFBLGFBQUEsTUFBQSxFQUFBLFdBQUEsYUFBQSxTQUFBLEVBQUE7QUFDQTs7QUFFQSxhQUFBLGdCQUFBLEdBQUE7QUFDQSxZQUFBLGNBQUEsRUFBQTtBQUNBLGVBQUEsWUFBQSxDQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLElBQUEsTUFBQSxLQUFBLE9BQUEsWUFBQSxJQUFBLElBQUEsYUFBQSxLQUFBLFFBQUEsRUFBQTtBQUNBLDRCQUFBLElBQUEsTUFBQSxJQUFBLElBQUEsTUFBQTtBQUNBLGFBRkEsTUFFQSxJQUFBLElBQUEsTUFBQSxLQUFBLE9BQUEsWUFBQSxJQUFBLElBQUEsYUFBQSxLQUFBLFFBQUEsRUFBQTtBQUNBLDRCQUFBLElBQUEsTUFBQSxJQUFBLElBQUEsTUFBQTtBQUNBO0FBQ0EsU0FOQTtBQU9BLGVBQUEsV0FBQSxHQUFBLFdBQUE7QUFDQTs7QUFFQTs7QUFHQSxXQUFBLFlBQUEsR0FBQSxZQUFBOztBQUVBLFdBQUEsT0FBQSxHQUFBLENBQUE7O0FBRUEsV0FBQSxHQUFBLEdBQUEsT0FBQSxXQUFBLENBQUEsR0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZUFBQSxJQUFBLEVBQUE7QUFDQSxLQUZBLENBQUE7OztBQUtBLFdBQUEsVUFBQSxHQUFBLEtBQUE7QUFDQSxXQUFBLFlBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxVQUFBLEdBQUEsQ0FBQSxPQUFBLFVBQUE7QUFDQSxLQUZBOztBQUlBLFdBQUEsY0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxhQUFBLEVBQUE7QUFDQSxzQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxJQUFBLFFBQUEsRUFBQTtBQUNBLDZCQUFBLFNBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLElBQUEsUUFBQSxFQUFBLENBQUEsRUFBQSxPQUFBLENBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSwyQkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsaUJBSkE7QUFLQTtBQUNBLFNBUkE7QUFTQSxlQUFBLFVBQUEsR0FBQSxLQUFBO0FBQ0EsS0FYQTs7QUFhQSxXQUFBLFNBQUEsR0FBQSxVQUFBLGFBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxXQUFBLEVBQUE7QUFDQSwwQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxRQUFBLEdBQUEsSUFBQTtBQUNBLGFBRkE7QUFHQSxTQUpBLE1BSUE7QUFDQSwwQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxRQUFBLEdBQUEsS0FBQTtBQUNBLGFBRkE7QUFHQTtBQUNBLEtBVkE7O0FBWUEsV0FBQSxnQkFBQSxHQUFBLFVBQUEsYUFBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLFdBQUEsS0FBQSxJQUFBLEVBQUE7QUFDQSxtQkFBQSxXQUFBLEdBQUEsS0FBQTtBQUNBO0FBQ0EsS0FKQTs7QUFNQSxXQUFBLFNBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsR0FBQSxFQUFBO0FBQ0EscUJBQUEsU0FBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsR0FBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE1BQUEsRUFBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxNQUFBO0FBQ0E7QUFDQSxTQUpBO0FBS0EsS0FOQTs7QUFRQSxXQUFBLFlBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUFBO0FBQ0EscUJBQUEsWUFBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE1BQUEsRUFBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxNQUFBO0FBQ0E7QUFDQTtBQUNBLFNBTEE7QUFNQSxLQVBBOztBQVNBLFdBQUEsTUFBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLFNBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxDQUFBLFVBQUEsT0FBQSxFQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBLFFBQUEsTUFBQSxDQUFBLENBQUEsRUFBQSxLQUFBO0FBQ0EsU0FGQTtBQUdBLFlBQUEsU0FBQSxPQUFBLElBQUEsQ0FBQSxVQUFBLENBQUEsRUFBQSxDQUFBLEVBQUE7QUFDQSxtQkFBQSxJQUFBLENBQUE7QUFDQSxTQUZBLENBQUE7QUFHQSxZQUFBLE9BQUEsTUFBQSxHQUFBLENBQUEsRUFBQTtBQUNBLHlCQUFBLE1BQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsYUFKQTtBQU1BLFNBUEEsTUFPQTtBQUNBLHlCQUFBLE1BQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLENBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsYUFKQTtBQUtBO0FBQ0EsS0F0QkE7O0FBd0JBLFdBQUEsU0FBQSxHQUFB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QSxDQUFBLEVBQUE7QUFDQSxlQUFBLE9BQUEsQ0FBQSxDQUFBLElBQUEsVUFBQTs7QUFFQSxZQUFBLFNBQUEsRUFBQSxRQUFBLE9BQUEsZUFBQSxDQUFBLENBQUEsQ0FBQSxFQUFBLFFBQUEsVUFBQSxFQUFBOzs7QUFHQSxZQUFBLE9BQUEsZUFBQSxDQUFBLE1BQUEsS0FBQSxDQUFBLEVBQUE7QUFBQSxtQkFBQSxlQUFBLENBQUEsSUFBQSxDQUFBLE1BQUE7QUFBQSxTQUFBLE1BQUE7QUFDQSxpQkFBQSxJQUFBLElBQUEsQ0FBQSxFQUFBLElBQUEsT0FBQSxlQUFBLENBQUEsTUFBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLE9BQUEsZUFBQSxDQUFBLENBQUEsRUFBQSxNQUFBLEtBQUEsT0FBQSxNQUFBLEVBQUE7QUFDQSwyQkFBQSxlQUFBLENBQUEsQ0FBQSxJQUFBLE1BQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQSxtQkFBQSxlQUFBLENBQUEsSUFBQSxDQUFBLE1BQUE7QUFDQTs7QUFFQSxLQWhCQTs7OztBQW9CQSxXQUFBLGVBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLFVBQUEsR0FBQSxFQUFBLE9BQUEsRUFBQSxHQUFBLEVBQUEsQ0FBQSxFQUFBLENBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxPQUFBLGVBQUE7QUFDQSxZQUFBLFFBQUEsS0FBQTtBQUNBLFlBQUEsVUFBQSxLQUFBLENBQUEsQ0FBQTtBQUNBLGFBQUEsSUFBQSxJQUFBLENBQUEsRUFBQSxJQUFBLE9BQUEsZUFBQSxDQUFBLE1BQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxNQUFBLE9BQUEsZUFBQSxDQUFBLENBQUEsQ0FBQTtBQUNBLG9CQUFBLEdBQUEsQ0FBQSxHQUFBO0FBQ0EsZ0JBQUEsSUFBQSxJQUFBLE1BQUEsQ0FBQSxFQUFBO0FBQ0Esd0JBQUEsSUFBQTtBQUNBLG9CQUFBLElBQUEsT0FBQSxDQUFBLEVBQUEsSUFBQSxPQUFBLElBQUEsT0FBQTtBQUNBLG9CQUFBLE9BQUEsSUFBQSxPQUFBO0FBQ0E7QUFDQTtBQUNBLFlBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSxnQkFBQSxTQUFBLEVBQUE7QUFDQSxtQkFBQSxJQUFBLElBQUEsQ0FBQTtBQUNBLG1CQUFBLE9BQUEsSUFBQSxPQUFBO0FBQ0EsbUJBQUEsZUFBQSxDQUFBLElBQUEsQ0FBQSxNQUFBO0FBQ0E7QUFDQSxLQW5CQTs7QUFxQkEsV0FBQSxhQUFBLEdBQUEsWUFBQTtBQUNBLFlBQUEsT0FBQSxFQUFBLE1BQUEsT0FBQSxlQUFBLEVBQUEsU0FBQSxPQUFBLGVBQUEsRUFBQTtBQUNBLHFCQUFBLGFBQUEsQ0FBQSxPQUFBLFNBQUEsRUFBQSxPQUFBLFlBQUEsRUFBQSxJQUFBO0FBQ0EsS0FIQTs7QUFNQSxXQUFBLFdBQUEsR0FBQSxZQUFBO0FBQ0EscUJBQUEsV0FBQSxDQUFBLE9BQUEsWUFBQSxFQUNBLElBREEsQ0FDQSxZQUFBO0FBQ0EsbUJBQUEsRUFBQSxDQUFBLE9BQUEsRUFBQSxFQUFBLFFBQUEsT0FBQSxTQUFBLEVBQUEsRUFBQSxFQUFBLFFBQUEsSUFBQSxFQUFBO0FBQ0EsU0FIQTtBQUlBLEtBTEE7Ozs7QUFTQSxXQUFBLHdCQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLGFBQUEsR0FBQSxFQUFBOztBQUVBLGlCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsSUFBQSxNQUFBLEtBQUEsT0FBQSxZQUFBLElBQUEsT0FBQSx3QkFBQSxDQUFBLE9BQUEsQ0FBQSxJQUFBLE1BQUEsS0FBQSxDQUFBLENBQUEsRUFBQTtBQUNBLG1CQUFBLHdCQUFBLENBQUEsSUFBQSxDQUFBLElBQUEsTUFBQTtBQUNBLFNBRkEsTUFFQSxJQUFBLElBQUEsTUFBQSxLQUFBLE9BQUEsWUFBQSxJQUFBLE9BQUEsd0JBQUEsQ0FBQSxPQUFBLENBQUEsSUFBQSxNQUFBLEtBQUEsQ0FBQSxDQUFBLEVBQUE7QUFDQSxtQkFBQSx3QkFBQSxDQUFBLElBQUEsQ0FBQSxJQUFBLE1BQUE7QUFDQTtBQUNBLEtBTkE7O0FBUUEsV0FBQSxhQUFBLEdBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsYUFBQSxDQUFBLE9BQUEsQ0FBQSxPQUFBLHdCQUFBLENBQUEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBLEVBQUE7QUFDQSxtQkFBQSxhQUFBLENBQUEsSUFBQSxDQUFBLE9BQUEsd0JBQUEsQ0FBQSxHQUFBLENBQUE7QUFDQSxTQUZBLE1BRUE7QUFDQSxnQkFBQSxJQUFBLE9BQUEsYUFBQSxDQUFBLE9BQUEsQ0FBQSxPQUFBLHdCQUFBLENBQUEsR0FBQSxDQUFBLENBQUE7QUFDQSxtQkFBQSxhQUFBLENBQUEsTUFBQSxDQUFBLENBQUEsRUFBQSxDQUFBO0FBQ0E7QUFDQSxLQVBBOztBQVNBLFdBQUEsZUFBQSxHQUFBLEVBQUE7O0FBRUEsV0FBQSxrQkFBQSxHQUFBLFlBQUE7QUFDQSxZQUFBLHFCQUFBLEVBQUE7QUFDQSxlQUFBLGFBQUEsQ0FBQSxPQUFBLENBQUEsVUFBQSxTQUFBLEVBQUE7QUFDQSxtQkFBQSxtQkFBQSxJQUFBLENBQUEsYUFBQSxrQkFBQSxDQUFBLE9BQUEsU0FBQSxFQUFBLFNBQUEsQ0FBQSxDQUFBO0FBQ0EsU0FGQTtBQUdBLGdCQUFBLEdBQUEsQ0FBQSxrQkFBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE9BQUEsRUFBQTtBQUNBLG9CQUFBLE9BQUEsQ0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLHVCQUFBLGVBQUEsQ0FBQSxJQUFBLENBQUEsTUFBQTtBQUNBLHVCQUFBLFVBQUE7QUFDQSxhQUhBO0FBSUEsU0FOQTtBQVFBLEtBYkE7O0FBZUEsUUFBQSxrQkFBQSxFQUFBO0FBQ0EsUUFBQSxVQUFBOztBQUVBLFdBQUEsa0JBQUEsR0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsQ0FBQSxlQUFBLEVBQUEsa0JBQUEsRUFBQTs7QUFFQSxZQUFBLGFBQUEsT0FBQSxlQUFBLENBQUEsQ0FBQSxFQUFBLFNBQUEsRUFBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLFlBQUEsWUFBQSxJQUFBLFNBQUE7QUFDQSxxQkFBQSxTQUFBOztBQUVBLFlBQUEsQ0FBQSxnQkFBQSxTQUFBLENBQUEsRUFBQSxnQkFBQSxTQUFBLElBQUEsRUFBQTtBQUNBLFlBQUEsZ0JBQUEsU0FBQSxFQUFBLE9BQUEsQ0FBQSxVQUFBLE1BQUEsQ0FBQSxDQUFBLEVBQUE7QUFDQSw0QkFBQSxTQUFBLEVBQUEsTUFBQSxDQUFBLGdCQUFBLFNBQUEsRUFBQSxPQUFBLENBQUEsVUFBQSxDQUFBLEVBQUEsQ0FBQTtBQUNBLFNBRkEsTUFFQTtBQUNBLDRCQUFBLFNBQUEsRUFBQSxJQUFBLENBQUEsVUFBQTtBQUNBO0FBQ0EsZUFBQSxlQUFBLEdBQUEsZUFBQTtBQUNBLEtBZEE7OztBQWtCQSxXQUFBLGFBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsV0FBQTs7QUFFQSxXQUFBLEdBQUEsR0FBQSxFQUFBOzs7O0FBS0EsV0FBQSxPQUFBLEdBQUEsWUFBQTs7QUFFQSxZQUFBLGtCQUFBLE9BQUEsT0FBQSxDQUFBLEdBQUEsQ0FBQSxVQUFBLE9BQUEsRUFBQTtBQUNBLG1CQUFBLE9BQUEsWUFBQSxHQUFBLEdBQUEsR0FBQSxPQUFBO0FBQ0EsU0FGQSxDQUFBO0FBR0EsYUFBQSxJQUFBLElBQUEsSUFBQSxPQUFBLGVBQUEsRUFBQTtBQUNBLG1CQUFBLGVBQUEsQ0FBQSxJQUFBLEVBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0NBQUEsSUFBQSxDQUFBLE9BQUEsR0FBQSxHQUFBLEdBQUE7QUFDQSxhQUZBO0FBR0E7QUFDQSxxQkFBQSxPQUFBLENBQUEsT0FBQSxTQUFBLEVBQUEsT0FBQSxZQUFBLEVBQUEsT0FBQSxhQUFBLEVBQUEsT0FBQSxlQUFBLEVBQUEsT0FBQSxZQUFBLEVBQUEsZUFBQSxFQUNBLElBREEsQ0FDQSxVQUFBLFdBQUEsRUFBQTtBQUNBLG9CQUFBLEdBQUEsQ0FBQSxjQUFBLEVBQUEsV0FBQTtBQUNBLG1CQUFBLFdBQUEsR0FBQSxXQUFBO0FBQ0EsU0FKQSxFQUtBLElBTEEsQ0FLQSxZQUFBO0FBQ0EsbUJBQUEsRUFBQSxDQUFBLG9CQUFBO0FBQ0EsU0FQQTtBQVFBLEtBbEJBOztBQW9CQSxXQUFBLGlCQUFBLEdBQUEsSUFBQTs7QUFFQSxXQUFBLElBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxPQUFBLEVBQUEsR0FBQSxFQUFBLEtBQUEsRUFBQTs7QUFFQSxZQUFBLGdCQUFBLFVBQUEsSUFBQSxDQUFBO0FBQ0EsdUJBQUEsT0FBQSxpQkFEQTtBQUVBLHlCQUFBLGlDQUZBO0FBR0Esd0JBQUEseUJBSEE7QUFJQSxxQkFBQTtBQUNBLDZCQUFBLHVCQUFBO0FBQ0EsMkJBQUEsT0FBQSxXQUFBO0FBQ0EsaUJBSEE7QUFJQSwwQkFBQSxrQkFBQSxZQUFBLEVBQUE7QUFDQSw0QkFBQSxHQUFBLENBQUEsT0FBQTtBQUNBLDJCQUFBLGFBQUEsV0FBQSxDQUFBLE1BQUEsRUFBQSxPQUFBLENBQUE7QUFDQSxpQkFQQTtBQVFBLDhCQUFBLHdCQUFBO0FBQ0EsMkJBQUEsT0FBQTtBQUNBLGlCQVZBO0FBV0EsMkJBQUEscUJBQUE7QUFDQSwyQkFBQSxPQUFBLFlBQUE7QUFDQSxpQkFiQTtBQWNBLHlCQUFBLG1CQUFBO0FBQ0EsMkJBQUEsR0FBQTtBQUNBLGlCQWhCQTtBQWlCQSxxQkFBQSxlQUFBO0FBQ0EsMkJBQUEsS0FBQTtBQUNBO0FBbkJBO0FBSkEsU0FBQSxDQUFBOztBQTJCQSxzQkFBQSxNQUFBLENBQUEsSUFBQSxDQUFBLFlBQUE7QUFDQSxvQkFBQSxHQUFBLENBQUEsUUFBQTtBQUNBLG1CQUFBLFVBQUE7QUFDQSxTQUhBO0FBSUEsS0FqQ0E7O0FBbUNBLFdBQUEsZUFBQSxHQUFBLFlBQUE7QUFDQSxlQUFBLGlCQUFBLEdBQUEsQ0FBQSxPQUFBLGlCQUFBO0FBQ0EsS0FGQTtBQUlBLENBbmJBOztBQ0FBLElBQUEsVUFBQSxDQUFBLFdBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsTUFBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUEsU0FBQSxFQUFBLFdBQUEsRUFBQSxZQUFBLEVBQUEsVUFBQSxFQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLFNBQUE7O0FBRUEsV0FBQSxXQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxhQUFBLE1BQUE7O0FBRUEsV0FBQSxZQUFBLEdBQUEsWUFBQTs7QUFFQSxXQUFBLFVBQUEsR0FBQSxVQUFBOztBQUVBLFdBQUEsZ0JBQUEsR0FBQSxhQUFBLE1BQUEsR0FBQSxRQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLE9BQUEsU0FBQSxDQUFBLElBQUEsQ0FBQSxNQUFBOztBQUVBLFdBQUEsR0FBQSxHQUFBLFlBQUE7QUFDQSxlQUFBLFdBQUEsQ0FBQSxJQUFBLENBQUEsR0FBQTtBQUNBLEtBRkE7O0FBSUEsV0FBQSxNQUFBLEdBQUEsTUFBQSxDOztBQUVBLFdBQUEsZ0JBQUEsR0FBQSxDQUFBLFFBQUEsRUFBQSxTQUFBLENBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLEtBQUE7O0FBRUEsV0FBQSxnQkFBQSxHQUFBLFVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsU0FBQSxHQUFBLElBQUE7QUFDQSxxQkFBQSxnQkFBQSxDQUFBLFdBQUEsRUFBQSxNQUFBO0FBQ0EsS0FIQTs7QUFLQSxXQUFBLFlBQUEsR0FBQSxVQUFBLFNBQUEsRUFBQTtBQUNBLFlBQUEsY0FBQSxlQUFBLElBQUEsY0FBQSxtQkFBQSxFQUFBLE9BQUEsSUFBQTtBQUNBLEtBRkE7O0FBSUEsV0FBQSxXQUFBLEdBQUEsVUFBQSxLQUFBLEVBQUE7QUFDQSxxQkFBQSxXQUFBLENBQUEsS0FBQSxFQUNBLElBREEsQ0FDQSxZQUFBO0FBQ0EsbUJBQUEsRUFBQSxDQUFBLE9BQUEsRUFBQSxFQUFBLFFBQUEsT0FBQSxNQUFBLEVBQUEsRUFBQSxFQUFBLFFBQUEsSUFBQSxFQUFBO0FBQ0EsU0FIQTtBQUlBLEtBTEE7O0FBT0EsV0FBQSxjQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsVUFBQSxDQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLElBQUEsVUFBQSxLQUFBLE9BQUEsS0FBQSxDQUFBLE1BQUEsSUFBQSxJQUFBLFdBQUEsS0FBQSxPQUFBLEtBQUEsQ0FBQSxNQUFBLEVBQUEsT0FBQSxJQUFBLEdBQUEsSUFBQSxTQUFBO0FBQ0EsU0FGQTtBQUdBLEtBSkE7O0FBTUEsV0FBQSxhQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLFdBQUEsR0FBQSxhQUFBLFdBQUE7QUFFQSxDQXREQTs7QUNBQSxJQUFBLE9BQUEsQ0FBQSxjQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUEsWUFBQSxFQUFBOztBQUVBLFFBQUEsZUFBQSxFQUFBOztBQUVBLGFBQUEsU0FBQSxDQUFBLEdBQUEsRUFBQTtBQUNBLGVBQUEsSUFBQSxJQUFBO0FBQ0E7O0FBRUEsaUJBQUEsWUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQkFBQSxNQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsY0FBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsU0FBQSxHQUFBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQkFBQSxNQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsTUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxJQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxHQUFBLFNBQUEsRUFBQSxJQUFBLENBQUE7QUFDQSxLQUZBOztBQUlBLGlCQUFBLGFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsSUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxrQkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsRUFBQSxJQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsTUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxDQUFBLHlCQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxFQUFBLEVBQUEsV0FBQSxTQUFBLEVBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxTQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLEtBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEdBQUEsR0FBQSxHQUFBLEtBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxZQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLFVBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEdBQUEsVUFBQSxHQUFBLFVBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxTQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxJQUFBLENBQUEsNEJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsQ0FBQTtBQUNBLEtBRkE7QUFHQSxpQkFBQSxXQUFBLEdBQUEsVUFBQSxLQUFBLEVBQUE7QUFDQSxjQUFBLE1BQUEsR0FBQSxhQUFBLE1BQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxDQUFBLGVBQUEsRUFBQSxLQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSkE7O0FBTUEsaUJBQUEsV0FBQSxHQUFBLFVBQUEsWUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLE1BQUEsQ0FBQSxtQkFBQSxhQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsYUFBQSxTQUFBLENBQUE7QUFDQSxLQUZBOztBQUlBLGlCQUFBLGdCQUFBLEdBQUEsVUFBQSxXQUFBLEVBQUEsTUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLElBQUEsQ0FBQSxtQkFBQSxNQUFBLEdBQUEsY0FBQSxFQUFBLFdBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxRQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsTUFBQSxDQUFBLG1CQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxlQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxvQ0FBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxrQkFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQ0FBQSxNQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsYUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxpQ0FBQSxNQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsa0JBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1DQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLE9BQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxNQUFBLEVBQUEsYUFBQSxFQUFBLGVBQUEsRUFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLEVBQUE7QUFDQSxhQUFBLE1BQUEsR0FBQSxNQUFBO0FBQ0EsYUFBQSxNQUFBLEdBQUEsY0FBQSxDQUFBLENBQUE7QUFDQSxhQUFBLGFBQUEsR0FBQSxhQUFBO0FBQ0EsYUFBQSxlQUFBLEdBQUEsZUFBQTtBQUNBLGFBQUEsWUFBQSxHQUFBLFlBQUE7Ozs7QUFJQSxxQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxJQUFBLE1BQUEsS0FBQSxNQUFBLElBQUEsSUFBQSxNQUFBLEtBQUEsS0FBQSxNQUFBLEVBQUE7QUFDQSxxQkFBQSxLQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0Esb0JBQUEsSUFBQSxhQUFBLEtBQUEsUUFBQSxFQUFBO0FBQ0EseUJBQUEsTUFBQSxHQUFBLElBQUEsTUFBQTtBQUNBLHlCQUFBLE1BQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSxpQkFIQSxNQUlBO0FBQ0EseUJBQUEsTUFBQSxHQUFBLElBQUEsTUFBQTtBQUNBLHlCQUFBLE1BQUEsR0FBQSxJQUFBLE1BQUE7QUFDQTtBQUNBLGFBVkEsTUFXQSxJQUFBLElBQUEsTUFBQSxLQUFBLEtBQUEsTUFBQSxJQUFBLElBQUEsTUFBQSxLQUFBLE1BQUEsRUFBQTtBQUNBLHFCQUFBLEtBQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSxvQkFBQSxJQUFBLGFBQUEsS0FBQSxTQUFBLEVBQUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EseUJBQUEsTUFBQSxHQUFBLElBQUEsTUFBQTtBQUNBLGlCQUhBLE1BSUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EseUJBQUEsTUFBQSxHQUFBLElBQUEsTUFBQTtBQUNBO0FBQ0E7QUFDQSxTQXZCQTs7QUF5QkEsZ0JBQUEsR0FBQSxDQUFBLE1BQUEsRUFBQSxJQUFBOztBQUVBLGVBQUEsTUFBQSxHQUFBLENBQUEsdUJBQUEsRUFBQSxJQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBdkNBOztBQXlDQSxpQkFBQSxjQUFBLEdBQUEsVUFBQSxFQUFBLEVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxHQUFBLEdBQUEsR0FBQSxFQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxXQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsT0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSwyQkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLE9BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxhQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsT0FBQSxFQUFBLE9BQUEsRUFBQSxHQUFBLEVBQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLEVBQUE7QUFDQSxhQUFBLE1BQUEsR0FBQSxNQUFBO0FBQ0EsYUFBQSxPQUFBLEdBQUEsT0FBQTtBQUNBLGFBQUEsT0FBQSxHQUFBLE9BQUE7QUFDQSxhQUFBLEdBQUEsR0FBQSxHQUFBO0FBQ0EsYUFBQSxHQUFBLEdBQUEsR0FBQTs7QUFFQSxlQUFBLE1BQUEsR0FBQSxDQUFBLDZCQUFBLEVBQUEsSUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQVZBOztBQVlBLFdBQUEsWUFBQTtBQUNBLENBMUpBO0FDQUEsSUFBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxtQkFBQSxLQUFBLENBQUEsT0FBQSxFQUFBO0FBQ0EsYUFBQSxVQURBO0FBRUEscUJBQUEscUJBRkE7QUFHQSxvQkFBQSxXQUhBO0FBSUEsaUJBQUE7QUFDQSx1QkFBQSxtQkFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsYUFBQSxZQUFBLENBQUEsYUFBQSxNQUFBLENBQUE7QUFDQSxhQUhBO0FBSUEsMEJBQUEsc0JBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLGFBQUEsa0JBQUEsQ0FBQSxhQUFBLE1BQUEsQ0FBQTtBQUNBLGFBTkE7QUFPQSx3QkFBQSxvQkFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsYUFBQSxhQUFBLENBQUEsYUFBQSxNQUFBLENBQUE7QUFDQTtBQVRBO0FBSkEsS0FBQTs7QUFpQkEsbUJBQUEsS0FBQSxDQUFBLGNBQUEsRUFBQTtBQUNBLGFBQUEsYUFEQTtBQUVBLHFCQUFBLDJCQUZBO0FBR0Esb0JBQUEsaUJBSEE7QUFJQSxpQkFBQTtBQUNBLHlCQUFBLHFCQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxhQUFBLGNBQUEsQ0FBQSxhQUFBLE1BQUEsRUFBQSxhQUFBLFNBQUEsQ0FBQTtBQUNBLGFBSEE7QUFJQSwwQkFBQSxzQkFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsYUFBQSxlQUFBLENBQUEsYUFBQSxNQUFBLEVBQUEsYUFBQSxTQUFBLENBQUE7QUFDQTtBQU5BO0FBSkEsS0FBQTs7QUFjQSxtQkFBQSxLQUFBLENBQUEsWUFBQSxFQUFBO0FBQ0EsYUFBQSw4QkFEQTtBQUVBLHFCQUFBLG9CQUZBO0FBR0Esb0JBQUEsZUFIQTtBQUlBLGlCQUFBO0FBQ0EsdUJBQUEsbUJBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLGFBQUEsY0FBQSxDQUFBLGFBQUEsS0FBQSxFQUFBLGFBQUEsTUFBQSxFQUFBLGFBQUEsU0FBQSxFQUFBLGFBQUEsR0FBQSxDQUFBO0FBQ0E7QUFIQTtBQUpBLEtBQUE7O0FBV0EsbUJBQUEsS0FBQSxDQUFBLGVBQUEsRUFBQTtBQUNBLGFBQUEscUJBREE7QUFFQSxxQkFBQSx1QkFGQTtBQUdBLG9CQUFBLGFBSEE7QUFJQSxpQkFBQTtBQUNBLHlCQUFBLHFCQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxhQUFBLGNBQUEsQ0FBQSxhQUFBLE1BQUEsRUFBQSxhQUFBLFNBQUEsQ0FBQTtBQUNBO0FBSEE7QUFKQSxLQUFBOztBQVdBLG1CQUFBLEtBQUEsQ0FBQSxjQUFBLEVBQUE7QUFDQSxhQUFBLGNBREE7QUFFQSxxQkFBQSwyQkFGQTtBQUdBLG9CQUFBO0FBSEEsS0FBQTs7QUFNQSxtQkFBQSxLQUFBLENBQUEsc0JBQUEsRUFBQTtBQUNBLGFBQUEsaUJBREE7QUFFQSxxQkFBQSw4QkFGQTtBQUdBLG9CQUFBO0FBSEEsS0FBQTs7QUFNQSxtQkFBQSxLQUFBLENBQUEsb0JBQUEsRUFBQTtBQUNBLGFBQUEsY0FEQTtBQUVBLHFCQUFBLHFCQUZBO0FBR0Esb0JBQUE7QUFIQSxLQUFBO0FBT0EsQ0F6RUE7QUNBQSxJQUFBLFVBQUEsQ0FBQSxhQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUEsV0FBQSxFQUFBLFNBQUEsRUFBQTs7QUFFQSxXQUFBLFlBQUEsR0FBQSxZQUFBO0FBQ0EsV0FBQSxTQUFBLEdBQUEsRUFBQTtBQUNBLFdBQUEsV0FBQSxHQUFBLFlBQUEsQ0FBQSxDQUFBO0FBQ0EsV0FBQSxTQUFBLEdBQUEsYUFBQSxNQUFBO0FBQ0EsV0FBQSxTQUFBLEdBQUEsYUFBQSxTQUFBOztBQUVBLGFBQUEsVUFBQSxHQUFBO0FBQ0EsZUFBQSxZQUFBLENBQUEsT0FBQSxDQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JBQUEsTUFBQSxTQUFBLE1BQUEsYUFBQSxTQUFBLEVBQUE7QUFDQSx1QkFBQSxTQUFBLENBQUEsSUFBQSxDQUFBLE1BQUEsUUFBQSxDQUFBO0FBQ0EsdUJBQUEsU0FBQSxDQUFBLElBQUEsQ0FBQSxNQUFBLFFBQUEsQ0FBQTtBQUNBO0FBQ0EsU0FMQTtBQU1BOztBQUVBOztBQUVBLGFBQUEsYUFBQSxHQUFBO0FBQ0EsZUFBQSxPQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsUUFBQSxZQUFBLENBQUEsRUFBQSxDQUFBLENBQUE7QUFDQSxhQUFBLElBQUEsSUFBQSxJQUFBLEtBQUEsRUFBQTtBQUNBLG1CQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsSUFBQTtBQUNBO0FBQ0E7O0FBRUE7OztBQUlBLGFBQUEsVUFBQSxHQUFBO0FBQ0EsZUFBQSxhQUFBLEdBQUEsRUFBQTtBQUNBLGVBQUEsV0FBQSxDQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLFlBQUEsRUFBQTtBQUNBLGlCQUFBLElBQUEsSUFBQSxJQUFBLEdBQUEsRUFBQTtBQUNBLDBCQUFBLElBQUEsQ0FBQSxJQUFBLElBQUEsQ0FBQTtBQUNBO0FBQ0EsbUJBQUEsYUFBQSxDQUFBLElBQUEsQ0FBQSxTQUFBO0FBQ0EsU0FOQTtBQU9BOzs7QUFHQTs7OztBQUlBLFdBQUEsSUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxLQUFBLEVBQUE7QUFDQSxZQUFBLFlBQUEsT0FBQSxTQUFBLENBQUEsS0FBQSxDQUFBOztBQUVBLFlBQUEsZ0JBQUEsVUFBQSxJQUFBLENBQUE7QUFDQSx1QkFBQSxPQUFBLGlCQURBO0FBRUEseUJBQUEsNkJBRkE7QUFHQSx3QkFBQSxrQkFIQTtBQUlBLHFCQUFBO0FBQ0EsMEJBQUEsa0JBQUEsWUFBQSxFQUFBO0FBQ0EsMkJBQUEsYUFBQSxjQUFBLENBQUEsTUFBQSxFQUFBLFNBQUEsQ0FBQTtBQUNBO0FBSEE7QUFKQSxTQUFBLENBQUE7O0FBV0Esc0JBQUEsTUFBQSxDQUFBLElBQUEsQ0FBQSxZQUFBO0FBQ0Esb0JBQUEsR0FBQSxDQUFBLFFBQUE7QUFDQSxtQkFBQSxVQUFBO0FBQ0EsU0FIQTtBQUlBLEtBbEJBOztBQW9CQSxXQUFBLGVBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxpQkFBQSxHQUFBLENBQUEsT0FBQSxpQkFBQTtBQUNBLEtBRkE7QUFHQSxDQXRFQTs7QUNBQSxJQUFBLFVBQUEsQ0FBQSxrQkFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLGlCQUFBLEVBQUEsWUFBQSxFQUFBLFdBQUEsRUFBQSxZQUFBLEVBQUEsTUFBQSxFQUFBLFFBQUEsRUFBQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxhQUFBLE1BQUE7O0FBRUEsV0FBQSxXQUFBLEdBQUEsUUFBQTs7QUFJQSxXQUFBLFdBQUEsR0FBQSxZQUFBOztBQUVBLGVBQUEsT0FBQSxHQUFBLEtBQUEsR0FBQTtBQUNBLGdCQUFBLEdBQUEsQ0FBQSxPQUFBLE9BQUE7QUFDQSxLQUpBOztBQVFBLGFBQUEsYUFBQSxHQUFBO0FBQ0EsZUFBQSxPQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsUUFBQSxPQUFBLFdBQUEsQ0FBQSxDQUFBLENBQUE7O0FBR0EsYUFBQSxJQUFBLElBQUEsSUFBQSxLQUFBLEVBQUE7QUFDQSxnQkFBQSxTQUFBLFlBQUEsSUFBQSxTQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsSUFBQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTs7O0FBSUEsYUFBQSxVQUFBLEdBQUE7QUFDQSxlQUFBLGFBQUEsR0FBQSxFQUFBO0FBQ0EsZUFBQSxXQUFBLENBQUEsQ0FBQSxFQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLFlBQUEsRUFBQTtBQUNBLGlCQUFBLElBQUEsSUFBQSxJQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBLFVBQUEsSUFBQSxDQUFBLElBQUEsSUFBQSxDQUFBO0FBQ0E7QUFDQSxtQkFBQSxhQUFBLENBQUEsSUFBQSxDQUFBLFNBQUE7QUFDQSxTQU5BO0FBT0E7OztBQUdBOztBQUdBLFdBQUEsYUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLE9BQUEsRUFBQSxPQUFBLEVBQUEsR0FBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLDBCQUFBLEtBQUE7QUFDQSxxQkFBQSxhQUFBLENBQUEsTUFBQSxFQUFBLE9BQUEsRUFBQSxPQUFBLEVBQUEsR0FBQSxFQUFBLEdBQUEsRUFDQSxJQURBLENBQ0EsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxjQUFBLEVBQUEsRUFBQSxRQUFBLE9BQUEsTUFBQSxFQUFBLFdBQUEsT0FBQSxXQUFBLEVBQUEsRUFBQSxFQUFBLFFBQUEsSUFBQSxFQUFBO0FBQ0EsU0FIQTtBQUlBLEtBTkE7O0FBVUEsV0FBQSxFQUFBLEdBQUEsWUFBQTtBQUNBLDBCQUFBLEtBQUEsQ0FBQSxPQUFBLFFBQUEsQ0FBQSxJQUFBO0FBQ0EsS0FGQTs7QUFJQSxXQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsMEJBQUEsT0FBQSxDQUFBLFFBQUE7QUFDQSxLQUZBO0FBR0EsQ0FoRUE7QUNBQSxJQUFBLE9BQUEsQ0FBQSxlQUFBLEVBQUEsWUFBQTtBQUNBLFdBQUEsQ0FDQSx1REFEQSxFQUVBLHFIQUZBLEVBR0EsaURBSEEsRUFJQSxpREFKQSxFQUtBLHVEQUxBLEVBTUEsdURBTkEsRUFPQSx1REFQQSxFQVFBLHVEQVJBLEVBU0EsdURBVEEsRUFVQSx1REFWQSxFQVdBLHVEQVhBLEVBWUEsdURBWkEsRUFhQSx1REFiQSxFQWNBLHVEQWRBLEVBZUEsdURBZkEsRUFnQkEsdURBaEJBLEVBaUJBLHVEQWpCQSxFQWtCQSx1REFsQkEsRUFtQkEsdURBbkJBLEVBb0JBLHVEQXBCQSxFQXFCQSx1REFyQkEsRUFzQkEsdURBdEJBLEVBdUJBLHVEQXZCQSxFQXdCQSx1REF4QkEsRUF5QkEsdURBekJBLEVBMEJBLHVEQTFCQSxDQUFBO0FBNEJBLENBN0JBOztBQ0FBLElBQUEsT0FBQSxDQUFBLGlCQUFBLEVBQUEsWUFBQTs7QUFFQSxRQUFBLHFCQUFBLFNBQUEsa0JBQUEsQ0FBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLElBQUEsS0FBQSxLQUFBLENBQUEsS0FBQSxNQUFBLEtBQUEsSUFBQSxNQUFBLENBQUEsQ0FBQTtBQUNBLEtBRkE7O0FBSUEsUUFBQSxZQUFBLENBQ0EsZUFEQSxFQUVBLHVCQUZBLEVBR0Esc0JBSEEsRUFJQSx1QkFKQSxFQUtBLHlEQUxBLEVBTUEsMENBTkEsRUFPQSxjQVBBLEVBUUEsdUJBUkEsRUFTQSxJQVRBLEVBVUEsaUNBVkEsRUFXQSwwREFYQSxFQVlBLDZFQVpBLENBQUE7O0FBZUEsV0FBQTtBQUNBLG1CQUFBLFNBREE7QUFFQSwyQkFBQSw2QkFBQTtBQUNBLG1CQUFBLG1CQUFBLFNBQUEsQ0FBQTtBQUNBO0FBSkEsS0FBQTtBQU9BLENBNUJBOztBQ0FBLElBQUEsU0FBQSxDQUFBLGVBQUEsRUFBQSxZQUFBO0FBQ0EsV0FBQTtBQUNBLGtCQUFBLEdBREE7QUFFQSxxQkFBQTtBQUZBLEtBQUE7QUFJQSxDQUxBO0FDQUEsSUFBQSxTQUFBLENBQUEsU0FBQSxFQUFBLFVBQUEsVUFBQSxFQUFBLFdBQUEsRUFBQSxXQUFBLEVBQUEsTUFBQSxFQUFBOztBQUVBLFdBQUE7QUFDQSxrQkFBQSxHQURBO0FBRUEsZUFBQSxFQUZBO0FBR0EscUJBQUEseUNBSEE7QUFJQSxjQUFBLGNBQUEsS0FBQSxFQUFBOztBQUVBLGtCQUFBLEtBQUEsR0FBQSxDQUNBLEVBQUEsT0FBQSxNQUFBLEVBQUEsT0FBQSxNQUFBLEVBREEsRUFFQSxFQUFBLE9BQUEsT0FBQSxFQUFBLE9BQUEsT0FBQSxFQUZBLEVBR0EsRUFBQSxPQUFBLGVBQUEsRUFBQSxPQUFBLE1BQUEsRUFIQSxFQUlBLEVBQUEsT0FBQSxjQUFBLEVBQUEsT0FBQSxhQUFBLEVBQUEsTUFBQSxJQUFBLEVBSkEsQ0FBQTs7QUFPQSxrQkFBQSxJQUFBLEdBQUEsSUFBQTs7QUFFQSxrQkFBQSxVQUFBLEdBQUEsWUFBQTtBQUNBLHVCQUFBLFlBQUEsZUFBQSxFQUFBO0FBQ0EsYUFGQTs7QUFJQSxrQkFBQSxNQUFBLEdBQUEsWUFBQTtBQUNBLDRCQUFBLE1BQUEsR0FBQSxJQUFBLENBQUEsWUFBQTtBQUNBLDJCQUFBLEVBQUEsQ0FBQSxhQUFBO0FBQ0EsaUJBRkE7QUFHQSxhQUpBOztBQU1BLGdCQUFBLFVBQUEsU0FBQSxPQUFBLEdBQUE7QUFDQSw0QkFBQSxlQUFBLEdBQUEsSUFBQSxDQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EsMEJBQUEsSUFBQSxHQUFBLElBQUE7QUFDQSxpQkFGQTtBQUdBLGFBSkE7O0FBTUEsZ0JBQUEsYUFBQSxTQUFBLFVBQUEsR0FBQTtBQUNBLHNCQUFBLElBQUEsR0FBQSxJQUFBO0FBQ0EsYUFGQTs7QUFJQTs7QUFFQSx1QkFBQSxHQUFBLENBQUEsWUFBQSxZQUFBLEVBQUEsT0FBQTtBQUNBLHVCQUFBLEdBQUEsQ0FBQSxZQUFBLGFBQUEsRUFBQSxVQUFBO0FBQ0EsdUJBQUEsR0FBQSxDQUFBLFlBQUEsY0FBQSxFQUFBLFVBQUE7QUFFQTs7QUF6Q0EsS0FBQTtBQTZDQSxDQS9DQTs7QUNBQSxJQUFBLFNBQUEsQ0FBQSxlQUFBLEVBQUEsVUFBQSxlQUFBLEVBQUE7O0FBRUEsV0FBQTtBQUNBLGtCQUFBLEdBREE7QUFFQSxxQkFBQSx5REFGQTtBQUdBLGNBQUEsY0FBQSxLQUFBLEVBQUE7QUFDQSxrQkFBQSxRQUFBLEdBQUEsZ0JBQUEsaUJBQUEsRUFBQTtBQUNBO0FBTEEsS0FBQTtBQVFBLENBVkEiLCJmaWxlIjoibWFpbi5qcyIsInNvdXJjZXNDb250ZW50IjpbIid1c2Ugc3RyaWN0JztcbndpbmRvdy5hcHAgPSBhbmd1bGFyLm1vZHVsZSgnRnVsbHN0YWNrR2VuZXJhdGVkQXBwJywgWydmc2FQcmVCdWlsdCcsICd1aS5yb3V0ZXInLCAndWkuYm9vdHN0cmFwJywgJ25nQW5pbWF0ZSddKTtcblxuYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHVybFJvdXRlclByb3ZpZGVyLCAkbG9jYXRpb25Qcm92aWRlcikge1xuICAgIC8vIFRoaXMgdHVybnMgb2ZmIGhhc2hiYW5nIHVybHMgKC8jYWJvdXQpIGFuZCBjaGFuZ2VzIGl0IHRvIHNvbWV0aGluZyBub3JtYWwgKC9hYm91dClcbiAgICAkbG9jYXRpb25Qcm92aWRlci5odG1sNU1vZGUodHJ1ZSk7XG4gICAgLy8gSWYgd2UgZ28gdG8gYSBVUkwgdGhhdCB1aS1yb3V0ZXIgZG9lc24ndCBoYXZlIHJlZ2lzdGVyZWQsIGdvIHRvIHRoZSBcIi9cIiB1cmwuXG4gICAgJHVybFJvdXRlclByb3ZpZGVyLm90aGVyd2lzZSgnLycpO1xuICAgIC8vIFRyaWdnZXIgcGFnZSByZWZyZXNoIHdoZW4gYWNjZXNzaW5nIGFuIE9BdXRoIHJvdXRlXG4gICAgJHVybFJvdXRlclByb3ZpZGVyLndoZW4oJy9hdXRoLzpwcm92aWRlcicsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgd2luZG93LmxvY2F0aW9uLnJlbG9hZCgpO1xuICAgIH0pO1xufSk7XG5cbi8vIFRoaXMgYXBwLnJ1biBpcyBmb3IgY29udHJvbGxpbmcgYWNjZXNzIHRvIHNwZWNpZmljIHN0YXRlcy5cbmFwcC5ydW4oZnVuY3Rpb24gKCRyb290U2NvcGUsIEF1dGhTZXJ2aWNlLCAkc3RhdGUpIHtcblxuICAgIC8vIFRoZSBnaXZlbiBzdGF0ZSByZXF1aXJlcyBhbiBhdXRoZW50aWNhdGVkIHVzZXIuXG4gICAgdmFyIGRlc3RpbmF0aW9uU3RhdGVSZXF1aXJlc0F1dGggPSBmdW5jdGlvbiAoc3RhdGUpIHtcbiAgICAgICAgcmV0dXJuIHN0YXRlLmRhdGEgJiYgc3RhdGUuZGF0YS5hdXRoZW50aWNhdGU7XG4gICAgfTtcblxuICAgIC8vICRzdGF0ZUNoYW5nZVN0YXJ0IGlzIGFuIGV2ZW50IGZpcmVkXG4gICAgLy8gd2hlbmV2ZXIgdGhlIHByb2Nlc3Mgb2YgY2hhbmdpbmcgYSBzdGF0ZSBiZWdpbnMuXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24gKGV2ZW50LCB0b1N0YXRlLCB0b1BhcmFtcykge1xuXG4gICAgICAgIGlmICghZGVzdGluYXRpb25TdGF0ZVJlcXVpcmVzQXV0aCh0b1N0YXRlKSkge1xuICAgICAgICAgICAgLy8gVGhlIGRlc3RpbmF0aW9uIHN0YXRlIGRvZXMgbm90IHJlcXVpcmUgYXV0aGVudGljYXRpb25cbiAgICAgICAgICAgIC8vIFNob3J0IGNpcmN1aXQgd2l0aCByZXR1cm4uXG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoQXV0aFNlcnZpY2UuaXNBdXRoZW50aWNhdGVkKCkpIHtcbiAgICAgICAgICAgIC8vIFRoZSB1c2VyIGlzIGF1dGhlbnRpY2F0ZWQuXG4gICAgICAgICAgICAvLyBTaG9ydCBjaXJjdWl0IHdpdGggcmV0dXJuLlxuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gQ2FuY2VsIG5hdmlnYXRpbmcgdG8gbmV3IHN0YXRlLlxuICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuXG4gICAgICAgIEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpLnRoZW4oZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgICAgIC8vIElmIGEgdXNlciBpcyByZXRyaWV2ZWQsIHRoZW4gcmVuYXZpZ2F0ZSB0byB0aGUgZGVzdGluYXRpb25cbiAgICAgICAgICAgIC8vICh0aGUgc2Vjb25kIHRpbWUsIEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpIHdpbGwgd29yaylcbiAgICAgICAgICAgIC8vIG90aGVyd2lzZSwgaWYgbm8gdXNlciBpcyBsb2dnZWQgaW4sIGdvIHRvIFwibG9naW5cIiBzdGF0ZS5cbiAgICAgICAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgICAgICAgICAgJHN0YXRlLmdvKHRvU3RhdGUubmFtZSwgdG9QYXJhbXMpO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAkc3RhdGUuZ28oJ2xvZ2luJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuXG4gICAgfSk7XG5cbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcblxuICAgIC8vIFJlZ2lzdGVyIG91ciAqYWJvdXQqIHN0YXRlLlxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhYm91dCcsIHtcbiAgICAgICAgdXJsOiAnL2Fib3V0JyxcbiAgICAgICAgY29udHJvbGxlcjogJ0Fib3V0Q29udHJvbGxlcicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvYWJvdXQvYWJvdXQuaHRtbCdcbiAgICB9KTtcblxufSk7XG5cbmFwcC5jb250cm9sbGVyKCdBYm91dENvbnRyb2xsZXInLCBmdW5jdGlvbiAoJHNjb3BlLCBGdWxsc3RhY2tQaWNzKSB7XG5cbiAgICAvLyBJbWFnZXMgb2YgYmVhdXRpZnVsIEZ1bGxzdGFjayBwZW9wbGUuXG4gICAgJHNjb3BlLmltYWdlcyA9IF8uc2h1ZmZsZShGdWxsc3RhY2tQaWNzKTtcblxufSk7IiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnZG9jcycsIHtcbiAgICAgICAgdXJsOiAnL2RvY3MnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2RvY3MvZG9jcy5odG1sJ1xuICAgIH0pO1xufSk7XG4iLCIoZnVuY3Rpb24gKCkge1xuXG4gICAgJ3VzZSBzdHJpY3QnO1xuXG4gICAgLy8gSG9wZSB5b3UgZGlkbid0IGZvcmdldCBBbmd1bGFyISBEdWgtZG95LlxuICAgIGlmICghd2luZG93LmFuZ3VsYXIpIHRocm93IG5ldyBFcnJvcignSSBjYW5cXCd0IGZpbmQgQW5ndWxhciEnKTtcblxuICAgIHZhciBhcHAgPSBhbmd1bGFyLm1vZHVsZSgnZnNhUHJlQnVpbHQnLCBbXSk7XG5cbiAgICBhcHAuZmFjdG9yeSgnU29ja2V0JywgZnVuY3Rpb24gKCkge1xuICAgICAgICBpZiAoIXdpbmRvdy5pbykgdGhyb3cgbmV3IEVycm9yKCdzb2NrZXQuaW8gbm90IGZvdW5kIScpO1xuICAgICAgICByZXR1cm4gd2luZG93LmlvKHdpbmRvdy5sb2NhdGlvbi5vcmlnaW4pO1xuICAgIH0pO1xuXG4gICAgLy8gQVVUSF9FVkVOVFMgaXMgdXNlZCB0aHJvdWdob3V0IG91ciBhcHAgdG9cbiAgICAvLyBicm9hZGNhc3QgYW5kIGxpc3RlbiBmcm9tIGFuZCB0byB0aGUgJHJvb3RTY29wZVxuICAgIC8vIGZvciBpbXBvcnRhbnQgZXZlbnRzIGFib3V0IGF1dGhlbnRpY2F0aW9uIGZsb3cuXG4gICAgYXBwLmNvbnN0YW50KCdBVVRIX0VWRU5UUycsIHtcbiAgICAgICAgbG9naW5TdWNjZXNzOiAnYXV0aC1sb2dpbi1zdWNjZXNzJyxcbiAgICAgICAgbG9naW5GYWlsZWQ6ICdhdXRoLWxvZ2luLWZhaWxlZCcsXG4gICAgICAgIGxvZ291dFN1Y2Nlc3M6ICdhdXRoLWxvZ291dC1zdWNjZXNzJyxcbiAgICAgICAgc2Vzc2lvblRpbWVvdXQ6ICdhdXRoLXNlc3Npb24tdGltZW91dCcsXG4gICAgICAgIG5vdEF1dGhlbnRpY2F0ZWQ6ICdhdXRoLW5vdC1hdXRoZW50aWNhdGVkJyxcbiAgICAgICAgbm90QXV0aG9yaXplZDogJ2F1dGgtbm90LWF1dGhvcml6ZWQnXG4gICAgfSk7XG5cbiAgICBhcHAuZmFjdG9yeSgnQXV0aEludGVyY2VwdG9yJywgZnVuY3Rpb24gKCRyb290U2NvcGUsICRxLCBBVVRIX0VWRU5UUykge1xuICAgICAgICB2YXIgc3RhdHVzRGljdCA9IHtcbiAgICAgICAgICAgIDQwMTogQVVUSF9FVkVOVFMubm90QXV0aGVudGljYXRlZCxcbiAgICAgICAgICAgIDQwMzogQVVUSF9FVkVOVFMubm90QXV0aG9yaXplZCxcbiAgICAgICAgICAgIDQxOTogQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsXG4gICAgICAgICAgICA0NDA6IEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0XG4gICAgICAgIH07XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3Qoc3RhdHVzRGljdFtyZXNwb25zZS5zdGF0dXNdLCByZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZXNwb25zZSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICB9KTtcblxuICAgIGFwcC5jb25maWcoZnVuY3Rpb24gKCRodHRwUHJvdmlkZXIpIHtcbiAgICAgICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaChbXG4gICAgICAgICAgICAnJGluamVjdG9yJyxcbiAgICAgICAgICAgIGZ1bmN0aW9uICgkaW5qZWN0b3IpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gJGluamVjdG9yLmdldCgnQXV0aEludGVyY2VwdG9yJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIF0pO1xuICAgIH0pO1xuXG4gICAgYXBwLnNlcnZpY2UoJ0F1dGhTZXJ2aWNlJywgZnVuY3Rpb24gKCRodHRwLCBTZXNzaW9uLCAkcm9vdFNjb3BlLCBBVVRIX0VWRU5UUywgJHEpIHtcblxuICAgICAgICBmdW5jdGlvbiBvblN1Y2Nlc3NmdWxMb2dpbihyZXNwb25zZSkge1xuICAgICAgICAgICAgdmFyIGRhdGEgPSByZXNwb25zZS5kYXRhO1xuICAgICAgICAgICAgU2Vzc2lvbi5jcmVhdGUoZGF0YS5pZCwgZGF0YS51c2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChBVVRIX0VWRU5UUy5sb2dpblN1Y2Nlc3MpO1xuICAgICAgICAgICAgcmV0dXJuIGRhdGEudXNlcjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIFVzZXMgdGhlIHNlc3Npb24gZmFjdG9yeSB0byBzZWUgaWYgYW5cbiAgICAgICAgLy8gYXV0aGVudGljYXRlZCB1c2VyIGlzIGN1cnJlbnRseSByZWdpc3RlcmVkLlxuICAgICAgICB0aGlzLmlzQXV0aGVudGljYXRlZCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiAhIVNlc3Npb24udXNlcjtcbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLmdldExvZ2dlZEluVXNlciA9IGZ1bmN0aW9uIChmcm9tU2VydmVyKSB7XG5cbiAgICAgICAgICAgIC8vIElmIGFuIGF1dGhlbnRpY2F0ZWQgc2Vzc2lvbiBleGlzdHMsIHdlXG4gICAgICAgICAgICAvLyByZXR1cm4gdGhlIHVzZXIgYXR0YWNoZWQgdG8gdGhhdCBzZXNzaW9uXG4gICAgICAgICAgICAvLyB3aXRoIGEgcHJvbWlzZS4gVGhpcyBlbnN1cmVzIHRoYXQgd2UgY2FuXG4gICAgICAgICAgICAvLyBhbHdheXMgaW50ZXJmYWNlIHdpdGggdGhpcyBtZXRob2QgYXN5bmNocm9ub3VzbHkuXG5cbiAgICAgICAgICAgIC8vIE9wdGlvbmFsbHksIGlmIHRydWUgaXMgZ2l2ZW4gYXMgdGhlIGZyb21TZXJ2ZXIgcGFyYW1ldGVyLFxuICAgICAgICAgICAgLy8gdGhlbiB0aGlzIGNhY2hlZCB2YWx1ZSB3aWxsIG5vdCBiZSB1c2VkLlxuXG4gICAgICAgICAgICBpZiAodGhpcy5pc0F1dGhlbnRpY2F0ZWQoKSAmJiBmcm9tU2VydmVyICE9PSB0cnVlKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRxLndoZW4oU2Vzc2lvbi51c2VyKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gTWFrZSByZXF1ZXN0IEdFVCAvc2Vzc2lvbi5cbiAgICAgICAgICAgIC8vIElmIGl0IHJldHVybnMgYSB1c2VyLCBjYWxsIG9uU3VjY2Vzc2Z1bExvZ2luIHdpdGggdGhlIHJlc3BvbnNlLlxuICAgICAgICAgICAgLy8gSWYgaXQgcmV0dXJucyBhIDQwMSByZXNwb25zZSwgd2UgY2F0Y2ggaXQgYW5kIGluc3RlYWQgcmVzb2x2ZSB0byBudWxsLlxuICAgICAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL3Nlc3Npb24nKS50aGVuKG9uU3VjY2Vzc2Z1bExvZ2luKS5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICB9KTtcblxuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMuc2lnbnVwID0gZnVuY3Rpb24oY3JlZGVudGlhbHMpe1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9zaWdudXAnLCBjcmVkZW50aWFscylcbiAgICAgICAgICAgIC50aGVuKG9uU3VjY2Vzc2Z1bExvZ2luKVxuICAgICAgICAgICAgLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHsgbWVzc2FnZTogJ0ludmFsaWQgc2lnbnVwIGNyZWRlbnRpYWxzLicgfSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLmxvZ2luID0gZnVuY3Rpb24gKGNyZWRlbnRpYWxzKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL2xvZ2luJywgY3JlZGVudGlhbHMpXG4gICAgICAgICAgICAgICAgLnRoZW4ob25TdWNjZXNzZnVsTG9naW4pXG4gICAgICAgICAgICAgICAgLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdCh7IG1lc3NhZ2U6ICdJbnZhbGlkIGxvZ2luIGNyZWRlbnRpYWxzLicgfSk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5sb2dvdXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvbG9nb3V0JykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgU2Vzc2lvbi5kZXN0cm95KCk7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KEFVVEhfRVZFTlRTLmxvZ291dFN1Y2Nlc3MpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICB9KTtcblxuICAgIGFwcC5zZXJ2aWNlKCdTZXNzaW9uJywgZnVuY3Rpb24gKCRyb290U2NvcGUsIEFVVEhfRVZFTlRTKSB7XG5cbiAgICAgICAgdmFyIHNlbGYgPSB0aGlzO1xuXG4gICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLm5vdEF1dGhlbnRpY2F0ZWQsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHNlbGYuZGVzdHJveSgpO1xuICAgICAgICB9KTtcblxuICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5zZXNzaW9uVGltZW91dCwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgc2VsZi5kZXN0cm95KCk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIHRoaXMuaWQgPSBudWxsO1xuICAgICAgICB0aGlzLnVzZXIgPSBudWxsO1xuXG4gICAgICAgIHRoaXMuY3JlYXRlID0gZnVuY3Rpb24gKHNlc3Npb25JZCwgdXNlcikge1xuICAgICAgICAgICAgdGhpcy5pZCA9IHNlc3Npb25JZDtcbiAgICAgICAgICAgIHRoaXMudXNlciA9IHVzZXI7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5kZXN0cm95ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgdGhpcy5pZCA9IG51bGw7XG4gICAgICAgICAgICB0aGlzLnVzZXIgPSBudWxsO1xuICAgICAgICB9O1xuXG4gICAgfSk7XG5cbn0pKCk7XG4iLCJhcHAuY29udHJvbGxlcignQ3JlYXRlZGJDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHN0YXRlLCBDcmVhdGVkYkZhY3RvcnkpIHtcblxuXHQkc2NvcGUuY3JlYXRlZERCID0gZmFsc2U7XG4gICAgICAgICRzY29wZS5jb2x1bW5BcnJheSA9IFtdO1xuXG5cdCRzY29wZS5hZGQgPSBmdW5jdGlvbigpIHtcblx0XHQkc2NvcGUuY29sdW1uQXJyYXkucHVzaCgnMScpO1xuXHR9XG5cblx0JHNjb3BlLmNyZWF0ZURCID0gZnVuY3Rpb24obmFtZSkge1xuXHRcdENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVEQihuYW1lKVxuXHRcdC50aGVuKGZ1bmN0aW9uKGRhdGEpIHtcblx0XHRcdCRzY29wZS5jcmVhdGVkREIgPSBkYXRhO1xuXHRcdH0pXG5cdH1cblxuXHQkc2NvcGUuY3JlYXRlVGFibGUgPSBmdW5jdGlvbih0YWJsZSwgREIpe1xuXHRcdENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVUYWJsZSh0YWJsZSwgREIpXG5cdFx0XHQkc3RhdGUuZ28oJ1RhYmxlJywge2RiTmFtZTogJHNjb3BlLmNyZWF0ZWREQi5kYk5hbWV9LCB7cmVsb2FkOnRydWV9KVxuXHR9XG59KTtcbiIsImFwcC5mYWN0b3J5KCdDcmVhdGVkYkZhY3RvcnknLCBmdW5jdGlvbiAoJGh0dHApIHtcblxuXHR2YXIgQ3JlYXRlZGJGYWN0b3J5ID0ge307XG5cblx0ZnVuY3Rpb24gcmVzVG9EYXRhKHJlcykge1xuICAgICAgICByZXR1cm4gcmVzLmRhdGE7XG4gICAgfVxuXG4gICAgQ3JlYXRlZGJGYWN0b3J5LmNyZWF0ZURCID0gZnVuY3Rpb24oZGJOYW1lKSB7XG4gICAgXHRyZXR1cm4gJGh0dHAucG9zdCgnL2FwaS9tYXN0ZXJkYicsIGRiTmFtZSlcbiAgICBcdC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgIENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVUYWJsZSA9IGZ1bmN0aW9uKHRhYmxlLCBjcmVhdGVkREIpIHtcbiAgICB0YWJsZS5kYk5hbWUgPSBjcmVhdGVkREIuZGJOYW1lO1xuICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL2NsaWVudGRiJywgdGFibGUpXG4gICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgIH1cblxuXHRyZXR1cm4gQ3JlYXRlZGJGYWN0b3J5OyBcbn0pXG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdjcmVhdGVkYicsIHtcbiAgICAgICAgdXJsOiAnL2NyZWF0ZWRiJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jcmVhdGVkYi9jcmVhdGVkYi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0NyZWF0ZWRiQ3RybCcsXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgXHRsb2dnZWRJblVzZXI6IGZ1bmN0aW9uKEF1dGhTZXJ2aWNlKSB7XG4gICAgICAgIFx0XHRyZXR1cm4gQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCk7XG4gICAgICAgIFx0fVxuICAgICAgICB9XG4gICAgfSk7XG5cbn0pOyIsImFwcC5jb250cm9sbGVyKCdIb21lQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsIGFsbERicywgJHN0YXRlKSB7XG5cblx0JHNjb3BlLmFsbERicyA9IGFsbERicztcbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ0hvbWVGYWN0b3J5JywgZnVuY3Rpb24gKCRodHRwKSB7XG5cblx0dmFyIEhvbWVGYWN0b3J5ID0ge307XG5cblx0ZnVuY3Rpb24gcmVzVG9EYXRhKHJlcykge1xuICAgICAgICByZXR1cm4gcmVzLmRhdGE7XG4gICAgfVxuXG4gICAgSG9tZUZhY3RvcnkuZ2V0QWxsRGJzID0gZnVuY3Rpb24oKXtcbiAgICBcdHJldHVybiAkaHR0cC5nZXQoJy9hcGkvbWFzdGVyZGInKVxuICAgIFx0LnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIEhvbWVGYWN0b3J5LmRlbGV0ZURCID0gZnVuY3Rpb24obmFtZSl7XG4gICAgXHRyZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL21hc3RlcmRiLycgKyBuYW1lKVxuICAgIFx0LnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuXHRyZXR1cm4gSG9tZUZhY3Rvcnk7IFxufSkiLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdIb21lJywge1xuICAgICAgICB1cmw6ICcvaG9tZScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvSG9tZS9Ib21lLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnSG9tZUN0cmwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgIFx0YWxsRGJzOiBmdW5jdGlvbihIb21lRmFjdG9yeSl7XG4gICAgICAgIFx0XHRyZXR1cm4gSG9tZUZhY3RvcnkuZ2V0QWxsRGJzKCk7XG4gICAgICAgIFx0fSxcbiAgICAgICAgICAgIGxvZ2dlZEluVXNlcjogZnVuY3Rpb24gKEF1dGhTZXJ2aWNlKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSk7XG59KTsiLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdsYW5kaW5nUGFnZScsIHtcbiAgICAgICAgdXJsOiAnLycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvbGFuZGluZ1BhZ2UvbGFuZGluZ1BhZ2UuaHRtbCdcbiAgICAgICAgfVxuICAgICk7XG5cbn0pOyIsIid1c2Ugc3RyaWN0JztcblxuYXBwLmRpcmVjdGl2ZSgnb2F1dGhCdXR0b24nLCBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiB7XG4gICAgc2NvcGU6IHtcbiAgICAgIHByb3ZpZGVyTmFtZTogJ0AnXG4gICAgfSxcbiAgICByZXN0cmljdDogJ0UnLFxuICAgIHRlbXBsYXRlVXJsOiAnL2pzL29hdXRoL29hdXRoLWJ1dHRvbi5odG1sJ1xuICB9XG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24oJHN0YXRlUHJvdmlkZXIpIHtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdsb2dpbicsIHtcbiAgICAgICAgdXJsOiAnL2xvZ2luJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9sb2dpbi9sb2dpbi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0xvZ2luQ3RybCdcbiAgICB9KTtcblxufSk7XG5cbmFwcC5jb250cm9sbGVyKCdMb2dpbkN0cmwnLCBmdW5jdGlvbigkc2NvcGUsIEF1dGhTZXJ2aWNlLCAkc3RhdGUpIHtcblxuICAgICRzY29wZS5sb2dpbiA9IHt9O1xuICAgICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgICAkc2NvcGUuc2VuZExvZ2luID0gZnVuY3Rpb24obG9naW5JbmZvKSB7XG5cbiAgICAgICAgJHNjb3BlLmVycm9yID0gbnVsbDtcblxuICAgICAgICBBdXRoU2VydmljZS5sb2dpbihsb2dpbkluZm8pLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oJ0hvbWUnKTtcbiAgICAgICAgfSkuY2F0Y2goZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAkc2NvcGUuZXJyb3IgPSAnSW52YWxpZCBsb2dpbiBjcmVkZW50aWFscy4nO1xuICAgICAgICB9KTtcblxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdtZW1iZXJzT25seScsIHtcbiAgICAgICAgdXJsOiAnL21lbWJlcnMtYXJlYScsXG4gICAgICAgIHRlbXBsYXRlOiAnPGltZyBuZy1yZXBlYXQ9XCJpdGVtIGluIHN0YXNoXCIgd2lkdGg9XCIzMDBcIiBuZy1zcmM9XCJ7eyBpdGVtIH19XCIgLz4nLFxuICAgICAgICBjb250cm9sbGVyOiBmdW5jdGlvbiAoJHNjb3BlLCBTZWNyZXRTdGFzaCkge1xuICAgICAgICAgICAgU2VjcmV0U3Rhc2guZ2V0U3Rhc2goKS50aGVuKGZ1bmN0aW9uIChzdGFzaCkge1xuICAgICAgICAgICAgICAgICRzY29wZS5zdGFzaCA9IHN0YXNoO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0sXG4gICAgICAgIC8vIFRoZSBmb2xsb3dpbmcgZGF0YS5hdXRoZW50aWNhdGUgaXMgcmVhZCBieSBhbiBldmVudCBsaXN0ZW5lclxuICAgICAgICAvLyB0aGF0IGNvbnRyb2xzIGFjY2VzcyB0byB0aGlzIHN0YXRlLiBSZWZlciB0byBhcHAuanMuXG4gICAgICAgIGRhdGE6IHtcbiAgICAgICAgICAgIGF1dGhlbnRpY2F0ZTogdHJ1ZVxuICAgICAgICB9XG4gICAgfSk7XG5cbn0pO1xuXG5hcHAuZmFjdG9yeSgnU2VjcmV0U3Rhc2gnLCBmdW5jdGlvbiAoJGh0dHApIHtcblxuICAgIHZhciBnZXRTdGFzaCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9tZW1iZXJzL3NlY3JldC1zdGFzaCcpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgfSk7XG4gICAgfTtcblxuICAgIHJldHVybiB7XG4gICAgICAgIGdldFN0YXNoOiBnZXRTdGFzaFxuICAgIH07XG5cbn0pOyIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnc2lnbnVwJywge1xuICAgICAgICB1cmw6ICcvc2lnbnVwJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9zaWdudXAvc2lnbnVwLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnU2lnbnVwQ3RybCdcbiAgICB9KTtcblxufSk7XG5cbmFwcC5jb250cm9sbGVyKCdTaWdudXBDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICAgJHNjb3BlLnNpZ251cCA9IHt9O1xuICAgICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgICAkc2NvcGUuc2VuZFNpZ251cCA9IGZ1bmN0aW9uIChzaWdudXBJbmZvKSB7XG4gICAgICAgICRzY29wZS5lcnJvciA9IG51bGw7XG4gICAgICAgIEF1dGhTZXJ2aWNlLnNpZ251cChzaWdudXBJbmZvKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbygnaG9tZScpO1xuICAgICAgICB9KS5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAkc2NvcGUuZXJyb3IgPSAnT29wcywgY2Fubm90IHNpZ24gdXAgd2l0aCB0aG9zZSBjcmVkZW50aWFscy4nO1xuICAgICAgICB9KTtcblxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmNvbnRyb2xsZXIoJ0Fzc29jaWF0aW9uSW5zdGFuY2VDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHVpYk1vZGFsSW5zdGFuY2UsIGZvcmVpZ25Db2xzLCBUYWJsZUZhY3RvcnksIEhvbWVGYWN0b3J5LCAkc3RhdGVQYXJhbXMsICRzdGF0ZSwgZm9yVGFibGUsIGZvclRhYmxlTmFtZSwgY3VyclRhYmxlLCBjb2xOYW1lLCBpZDEpIHtcblxuICAkc2NvcGUuZGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZTtcblxuICAkc2NvcGUuc2luZ2xlVGFibGUgPSBmb3JUYWJsZTtcblxuICAkc2NvcGUuVGFibGVOYW1lID0gZm9yVGFibGVOYW1lO1xuXG4gICRzY29wZS5jdXJyVGFibGUgPSBjdXJyVGFibGU7XG5cbiAgJHNjb3BlLmNvbE5hbWUgPSBjb2xOYW1lO1xuXG4gICRzY29wZS5pZDEgPSBpZDE7XG5cbiAgJHNjb3BlLnNldFNlbGVjdGVkID0gZnVuY3Rpb24oKXtcblxuICAgICRzY29wZS5jdXJyUm93ID0gdGhpcy5yb3c7XG4gICAgY29uc29sZS5sb2coJHNjb3BlLmN1cnJSb3cpO1xuICB9XG5cbiBcblxuICBmdW5jdGlvbiBDcmVhdGVDb2x1bW5zKCl7XG4gICAgJHNjb3BlLmNvbHVtbnMgPSBbXTtcbiAgICB2YXIgdGFibGUgPSBmb3JUYWJsZVswXTtcblxuXG4gICAgZm9yKHZhciBwcm9wIGluIHRhYmxlKXtcbiAgICAgIGlmKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpe1xuICAgICAgICAkc2NvcGUuY29sdW1ucy5wdXNoKHByb3ApOyAgXG4gICAgICB9IFxuICAgIH1cbiAgfVxuXG4gICAgQ3JlYXRlQ29sdW1ucygpO1xuXG5cbiAgICAvL3RoaXMgZnVuY3Rpb24gd2lsbCByZSBydW4gd2hlbiB0aGUgZmlsdGVyIGZ1bmN0aW9uIGlzIGludm9rZWQsIGluIG9yZGVyIHRvIHJlcG9wdWxhdGUgdGhlIHRhYmxlXG4gICAgZnVuY3Rpb24gQ3JlYXRlUm93cygpIHtcbiAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkgPSBbXTtcbiAgICAgICAgZm9yVGFibGUuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIHZhciByb3dWYWx1ZXMgPSBbXTtcbiAgICAgICAgICAgIGZvciAodmFyIHByb3AgaW4gcm93KSB7XG4gICAgICAgICAgICAgICAgaWYgKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpIHJvd1ZhbHVlcy5wdXNoKHJvd1twcm9wXSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5LnB1c2gocm93VmFsdWVzKVxuICAgICAgICB9KVxuICAgIH1cblxuICAgIC8vIFNvcnQgdGhlIHZhbHVlcyBpbiBzaW5nbGVUYWJsZSBzbyB0aGF0IGFsbCB0aGUgdmFsdWVzIGZvciBhIGdpdmVuIHJvdyBhcmUgZ3JvdXBlZFxuICAgIENyZWF0ZVJvd3MoKTtcblxuXG4gICRzY29wZS5zZXRGb3JlaWduS2V5ID0gZnVuY3Rpb24oZGJOYW1lLCB0YmxOYW1lLCBjb2xOYW1lLCBpZDEsIGlkMil7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoKTtcbiAgICBUYWJsZUZhY3Rvcnkuc2V0Rm9yZWlnbktleShkYk5hbWUsIHRibE5hbWUsIGNvbE5hbWUsIGlkMSwgaWQyKVxuICAgIC50aGVuKGZ1bmN0aW9uKCl7XG4gICAgICAgICRzdGF0ZS5nbygnVGFibGUuU2luZ2xlJywgeyBkYk5hbWU6ICRzY29wZS5kYk5hbWUsIHRhYmxlTmFtZTogJHNjb3BlLmN1cnJUYWJsZSB9LCB7IHJlbG9hZDogdHJ1ZSB9KVxuICAgIH0pXG4gIH1cblxuXG5cbiAgJHNjb3BlLm9rID0gZnVuY3Rpb24gKCkge1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmNsb3NlKCRzY29wZS5zZWxlY3RlZC5pdGVtKTtcbiAgfTtcblxuICAkc2NvcGUuY2FuY2VsID0gZnVuY3Rpb24gKCkge1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmRpc21pc3MoJ2NhbmNlbCcpO1xuICB9O1xufSk7IiwiYXBwLmNvbnRyb2xsZXIoJ2RlbGV0ZURCQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsICR1aWJNb2RhbCwgJGxvZykge1xuXG4gICRzY29wZS5pdGVtcyA9IFsnaXRlbTEnLCAnaXRlbTInLCAnaXRlbTMnXTtcblxuICAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQgPSB0cnVlO1xuXG4gICRzY29wZS5vcGVuID0gZnVuY3Rpb24gKHNpemUpIHtcblxuICAgIHZhciBtb2RhbEluc3RhbmNlID0gJHVpYk1vZGFsLm9wZW4oe1xuICAgICAgYW5pbWF0aW9uOiAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQsXG4gICAgICB0ZW1wbGF0ZVVybDogJ2RlbGV0ZURCQ29udGVudC5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdkZWxldGVEQkluc3RhbmNlQ3RybCcsXG4gICAgICBzaXplOiBzaXplLFxuICAgICAgcmVzb2x2ZToge1xuICAgICAgICBpdGVtczogZnVuY3Rpb24gKCkge1xuICAgICAgICAgIHJldHVybiAkc2NvcGUuaXRlbXM7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcblxuICAgIG1vZGFsSW5zdGFuY2UucmVzdWx0LnRoZW4oZnVuY3Rpb24gKHNlbGVjdGVkSXRlbSkge1xuICAgICAgJHNjb3BlLnNlbGVjdGVkID0gc2VsZWN0ZWRJdGVtO1xuICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICRsb2cuaW5mbygnTW9kYWwgZGlzbWlzc2VkIGF0OiAnICsgbmV3IERhdGUoKSk7XG4gICAgfSk7XG4gIH07XG5cbiAgJHNjb3BlLnRvZ2dsZUFuaW1hdGlvbiA9IGZ1bmN0aW9uICgpIHtcbiAgICAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQgPSAhJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkO1xuICB9O1xuXG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ2RlbGV0ZURCSW5zdGFuY2VDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgJHVpYk1vZGFsSW5zdGFuY2UsIGl0ZW1zLCBUYWJsZUZhY3RvcnksIEhvbWVGYWN0b3J5LCAkc3RhdGVQYXJhbXMsICRzdGF0ZSkge1xuXG5cbiAgJHNjb3BlLmRyb3BEYlRleHQgPSAnRFJPUCBEQVRBQkFTRSdcbiAgJHNjb3BlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG5cbiAgJHNjb3BlLmRlbGV0ZVRoZURiID0gZnVuY3Rpb24oKXtcbiAgICAkdWliTW9kYWxJbnN0YW5jZS5jbG9zZSgkc2NvcGUuc2VsZWN0ZWQuaXRlbSk7XG4gICAgVGFibGVGYWN0b3J5LmRlbGV0ZURiKCRzY29wZS5kYk5hbWUpXG4gICAgLnRoZW4oZnVuY3Rpb24oKXtcbiAgICAgIEhvbWVGYWN0b3J5LmRlbGV0ZURCKCRzY29wZS5kYk5hbWUpXG4gICAgfSlcbiAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICRzdGF0ZS5nbygnSG9tZScsIHt9LCB7cmVsb2FkIDogdHJ1ZX0pXG4gICAgfSlcbiAgfVxuXG4gICRzY29wZS5pdGVtcyA9IGl0ZW1zO1xuICAkc2NvcGUuc2VsZWN0ZWQgPSB7XG4gICAgaXRlbTogJHNjb3BlLml0ZW1zWzBdXG4gIH07XG5cbiAgJHNjb3BlLm9rID0gZnVuY3Rpb24gKCkge1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmNsb3NlKCRzY29wZS5zZWxlY3RlZC5pdGVtKTtcbiAgfTtcblxuICAkc2NvcGUuY2FuY2VsID0gZnVuY3Rpb24gKCkge1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmRpc21pc3MoJ2NhbmNlbCcpO1xuICB9O1xufSk7IiwiYXBwLmNvbnRyb2xsZXIoJ0RlbGV0ZURiQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUpIHtcblxuICAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQgPSB0cnVlO1xuXG4gICRzY29wZS5vcGVuID0gZnVuY3Rpb24gKHNpemUpIHtcblxuICAgIHZhciBtb2RhbEluc3RhbmNlID0gJHVpYk1vZGFsLm9wZW4oe1xuICAgICAgYW5pbWF0aW9uOiAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQsXG4gICAgICB0ZW1wbGF0ZVVybDogJ2RlbGV0ZURiQ29udGVudC5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICdEZWxldGVEYkluc3RhbmNlQ3RybCcsXG4gICAgICBzaXplOiBzaXplLFxuICAgICAgcmVzb2x2ZToge1xuICAgICAgICBpdGVtczogZnVuY3Rpb24gKCkge1xuICAgICAgICAgIHJldHVybiAkc2NvcGUuaXRlbXM7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcblxuICAgIG1vZGFsSW5zdGFuY2UucmVzdWx0LnRoZW4oZnVuY3Rpb24gKHNlbGVjdGVkSXRlbSkge1xuICAgICAgJHNjb3BlLnNlbGVjdGVkID0gc2VsZWN0ZWRJdGVtO1xuICAgIH0sIGZ1bmN0aW9uICgpIHtcbiAgICAgICRsb2cuaW5mbygnTW9kYWwgZGlzbWlzc2VkIGF0OiAnICsgbmV3IERhdGUoKSk7XG4gICAgfSk7XG4gIH07XG5cbn0pO1xuXG5cbmFwcC5jb250cm9sbGVyKCdEZWxldGVEYkluc3RhbmNlQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsICR1aWJNb2RhbEluc3RhbmNlLCBpdGVtcywgJHN0YXRlUGFyYW1zLCBUYWJsZUZhY3RvcnkpIHtcblxuICAkc2NvcGUuZGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZVxuXG4gICRzY29wZS5kcm9wRGF0YWJhc2UgPSAnRFJPUCBEQVRBQkFTRSdcblxuICAkc2NvcGUuZGVsZXRlID0gZnVuY3Rpb24gKCkge1xuICAgIFRhYmxlRmFjdG9yeS5kZWxldGVEYigkc2NvcGUuZGJOYW1lKVxuICAgIC8vICRzdGF0ZS5nbygnSG9tZScsIHt9LCB7cmVsb2FkIDogdHJ1ZX0pXG4gIH07XG5cbiAgJHNjb3BlLmNhbmNlbCA9IGZ1bmN0aW9uICgpIHtcbiAgICAkdWliTW9kYWxJbnN0YW5jZS5kaXNtaXNzKCdjYW5jZWwnKTtcbiAgfTtcbn0pOyIsImFwcC5jb250cm9sbGVyKCdKb2luVGFibGVDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMsIGpvaW5UYWJsZSkge1xuXG4gICAgJHNjb3BlLmpvaW5UYWJsZSA9IGpvaW5UYWJsZTtcblxuXG5cdGZ1bmN0aW9uIENyZWF0ZUNvbHVtbnMoKXtcblx0XHQkc2NvcGUuY29sdW1ucyA9IFtdO1xuXHRcdHZhciB0YWJsZSA9ICRzY29wZS5qb2luVGFibGVbMF07XG5cblxuXHRcdGZvcih2YXIgcHJvcCBpbiB0YWJsZSl7XG5cdFx0XHRpZihwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKXtcblx0XHRcdFx0JHNjb3BlLmNvbHVtbnMucHVzaChwcm9wKTtcdFxuXHRcdFx0fSBcblx0XHR9XG5cdH1cblxuICAgIENyZWF0ZUNvbHVtbnMoKTtcblxuXG4gICAgLy90aGlzIGZ1bmN0aW9uIHdpbGwgcmUgcnVuIHdoZW4gdGhlIGZpbHRlciBmdW5jdGlvbiBpcyBpbnZva2VkLCBpbiBvcmRlciB0byByZXBvcHVsYXRlIHRoZSB0YWJsZVxuICAgIGZ1bmN0aW9uIENyZWF0ZVJvd3MoKSB7XG4gICAgXHR2YXIgYWxpYXM7XG4gICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5ID0gW107XG4gICAgICAgIGpvaW5UYWJsZS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgdmFyIHJvd1ZhbHVlcyA9IFtdO1xuICAgICAgICAgICAgZm9yICh2YXIgcHJvcCBpbiByb3cpIHtcbiAgICAgICAgICAgICAgICBpZiAocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jykgcm93VmFsdWVzLnB1c2gocm93W3Byb3BdKVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkucHVzaChyb3dWYWx1ZXMpXG4gICAgICAgIH0pXG4gICAgfVxuXG4gICAgLy8gU29ydCB0aGUgdmFsdWVzIGluIHNpbmdsZVRhYmxlIHNvIHRoYXQgYWxsIHRoZSB2YWx1ZXMgZm9yIGEgZ2l2ZW4gcm93IGFyZSBncm91cGVkXG4gICAgQ3JlYXRlUm93cygpO1xuXG5cbn0pIiwiYXBwLmNvbnRyb2xsZXIoJ1F1ZXJ5VGFibGVDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcblxuICAgICRzY29wZS5xRmlsdGVyID0gZnVuY3Rpb24ocmVmZXJlbmNlU3RyaW5nLCB2YWwpe1xuICAgICAgICBpZighcmVmZXJlbmNlU3RyaW5nKSByZXR1cm4gdHJ1ZTtcbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBmb3IodmFyIHByb3AgaW4gdmFsKXtcbiAgICAgICAgICAgICAgICB2YXIgY2VsbFZhbCA9IHZhbFtwcm9wXS50b1N0cmluZygpLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgICAgICAgICAgdmFyIHNlYXJjaFZhbCA9IHJlZmVyZW5jZVN0cmluZy50b1N0cmluZygpLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgICAgICAgICAgY29uc29sZS5sb2coY2VsbFZhbCwgc2VhcmNoVmFsLCBjZWxsVmFsLmluZGV4T2Yoc2VhcmNoVmFsKSAhPT0gLTEpXG4gICAgICAgICAgICAgICAgaWYoY2VsbFZhbC5pbmRleE9mKHNlYXJjaFZhbCkgIT09IC0xKSByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG59KSIsImFwcC5jb250cm9sbGVyKCdTaW5nbGVUYWJsZUN0cmwnLCBmdW5jdGlvbigkc2NvcGUsIFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zLCBzaW5nbGVUYWJsZSwgJHdpbmRvdywgJHN0YXRlLCAkdWliTW9kYWwsIGFzc29jaWF0aW9ucywgJGxvZykge1xuXG4gICAgLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1B1dHRpbmcgc3R1ZmYgb24gc2NvcGUvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG5cbiAgICAkc2NvcGUudGhlRGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZTtcbiAgICAkc2NvcGUudGhlVGFibGVOYW1lID0gJHN0YXRlUGFyYW1zLnRhYmxlTmFtZTtcbiAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSBzaW5nbGVUYWJsZVswXTtcbiAgICAkc2NvcGUuc2VsZWN0ZWRBbGwgPSBmYWxzZTtcbiAgICAkc2NvcGUuYXNzb2NpYXRpb25zID0gYXNzb2NpYXRpb25zO1xuXG4gICAgaWYoJHNjb3BlLmFzc29jaWF0aW9uc1swXVsnVGhyb3VnaCddID09PSAkc3RhdGVQYXJhbXMudGFibGVOYW1lKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKCdIRUxMTycpO1xuICAgICAgICAkc3RhdGUuZ28oJ1RhYmxlLlRocm91Z2gnLCB7ZGJOYW1lIDogJHN0YXRlUGFyYW1zLmRiTmFtZSwgdGFibGVOYW1lIDogJHN0YXRlUGFyYW1zLnRhYmxlTmFtZX0pXG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZm9yZWlnbkNvbHVtbk9iaigpIHtcbiAgICAgICAgdmFyIGZvcmVpZ25Db2xzID0ge307XG4gICAgICAgICRzY29wZS5hc3NvY2lhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIGlmIChyb3cuVGFibGUxID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmIHJvdy5SZWxhdGlvbnNoaXAxID09PSAnaGFzT25lJykge1xuICAgICAgICAgICAgICAgIGZvcmVpZ25Db2xzW3Jvdy5BbGlhczFdID0gcm93LlRhYmxlMlxuICAgICAgICAgICAgfSBlbHNlIGlmIChyb3cuVGFibGUyID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmIHJvdy5SZWxhdGlvbnNoaXAyID09PSAnaGFzT25lJykge1xuICAgICAgICAgICAgICAgIGZvcmVpZ25Db2xzW3Jvdy5BbGlhczJdID0gcm93LlRhYmxlMVxuICAgICAgICAgICAgfVxuICAgICAgICB9KVxuICAgICAgICAkc2NvcGUuZm9yZWlnbkNvbHMgPSBmb3JlaWduQ29scztcbiAgICB9XG5cbiAgICBmb3JlaWduQ29sdW1uT2JqKCk7XG5cblxuICAgICRzY29wZS5jdXJyZW50VGFibGUgPSAkc3RhdGVQYXJhbXM7XG5cbiAgICAkc2NvcGUubXlJbmRleCA9IDE7XG5cbiAgICAkc2NvcGUuaWRzID0gJHNjb3BlLnNpbmdsZVRhYmxlLm1hcChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgcmV0dXJuIHJvdy5pZDtcbiAgICB9KVxuXG4gICAgLy9kZWxldGUgYSByb3cgXG4gICAgJHNjb3BlLnNob3dEZWxldGUgPSBmYWxzZTtcbiAgICAkc2NvcGUudG9nZ2xlRGVsZXRlID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICRzY29wZS5zaG93RGVsZXRlID0gISRzY29wZS5zaG93RGVsZXRlXG4gICAgfVxuXG4gICAgJHNjb3BlLmRlbGV0ZVNlbGVjdGVkID0gZnVuY3Rpb24oZGIsIHRhYmxlLCBpbnN0YW5jZUFycmF5KSB7XG4gICAgICAgIGluc3RhbmNlQXJyYXkuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIGlmIChyb3cuc2VsZWN0ZWQpIHtcbiAgICAgICAgICAgICAgICBUYWJsZUZhY3RvcnkucmVtb3ZlUm93KGRiLCB0YWJsZSwgcm93Wyd2YWx1ZXMnXVswXVsndmFsdWUnXSlcbiAgICAgICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB9XG4gICAgICAgIH0pXG4gICAgICAgICRzY29wZS5zaG93RGVsZXRlID0gZmFsc2U7XG4gICAgfVxuXG4gICAgJHNjb3BlLnNlbGVjdEFsbCA9IGZ1bmN0aW9uKGluc3RhbmNlQXJyYXkpIHtcbiAgICAgICAgaWYgKCRzY29wZS5zZWxlY3RlZEFsbCkge1xuICAgICAgICAgICAgaW5zdGFuY2VBcnJheS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgICAgIHJvdy5zZWxlY3RlZCA9IHRydWU7XG4gICAgICAgICAgICB9KVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgaW5zdGFuY2VBcnJheS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgICAgIHJvdy5zZWxlY3RlZCA9IGZhbHNlO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS51bmNoZWNrU2VsZWN0QWxsID0gZnVuY3Rpb24oaW5zdGFuY2VBcnJheSkge1xuICAgICAgICBpZiAoJHNjb3BlLnNlbGVjdGVkQWxsID09PSB0cnVlKSB7XG4gICAgICAgICAgICAkc2NvcGUuc2VsZWN0ZWRBbGwgPSBmYWxzZTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS5yZW1vdmVSb3cgPSBmdW5jdGlvbihkYiwgdGFibGUsIHJvdykge1xuICAgICAgICBUYWJsZUZhY3RvcnkucmVtb3ZlUm93KGRiLCB0YWJsZSwgcm93KVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0O1xuICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgIH0pXG4gICAgfVxuXG4gICAgJHNjb3BlLnJlbW92ZUNvbHVtbiA9IGZ1bmN0aW9uKGRiLCB0YWJsZSwgY29sdW1uTmFtZSkge1xuICAgICAgICBUYWJsZUZhY3RvcnkucmVtb3ZlQ29sdW1uKGRiLCB0YWJsZSwgY29sdW1uTmFtZSlcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHJlc3VsdDtcbiAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICAgICAgQ3JlYXRlQ29sdW1ucygpO1xuICAgICAgICAgICAgfSlcbiAgICB9XG5cbiAgICAkc2NvcGUubmV3Um93ID0gZnVuY3Rpb24oZGIsIHRhYmxlLCBhcnIpIHtcbiAgICAgICAgdmFyIGFsbElkcyA9IFtdO1xuICAgICAgICBhcnIuZm9yRWFjaChmdW5jdGlvbihyb3dEYXRhKSB7XG4gICAgICAgICAgICBhbGxJZHMucHVzaChyb3dEYXRhLnZhbHVlc1swXS52YWx1ZSlcbiAgICAgICAgfSlcbiAgICAgICAgdmFyIHNvcnRlZCA9IGFsbElkcy5zb3J0KGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgICAgICAgIHJldHVybiBiIC0gYVxuICAgICAgICB9KVxuICAgICAgICBpZiAoc29ydGVkLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgIFRhYmxlRmFjdG9yeS5hZGRSb3coZGIsIHRhYmxlLCBzb3J0ZWRbMF0gKyAxKVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICB9KVxuXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBUYWJsZUZhY3RvcnkuYWRkUm93KGRiLCB0YWJsZSwgMSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0O1xuICAgICAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS5hZGRDb2x1bW4gPSBmdW5jdGlvbihkYiwgdGFibGUpIHtcbiAgICAgICAgdmFyIGNvbE51bXMgPSAkc2NvcGUuY29sdW1ucy5qb2luKCcgJykubWF0Y2goL1xcZCsvZyk7XG4gICAgICAgIGlmIChjb2xOdW1zKSB7XG4gICAgICAgICAgICB2YXIgc29ydGVkTnVtcyA9IGNvbE51bXMuc29ydChmdW5jdGlvbihhLCBiKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGIgLSBhXG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgdmFyIG51bUluTmV3ID0gTnVtYmVyKHNvcnRlZE51bXNbMF0pICsgMTtcbiAgICAgICAgICAgIHZhciBuYW1lTmV3Q29sID0gJ0NvbHVtbiAnICsgbnVtSW5OZXcudG9TdHJpbmcoKTtcblxuICAgICAgICAgICAgVGFibGVGYWN0b3J5LmFkZENvbHVtbihkYiwgdGFibGUsIG5hbWVOZXdDb2wpXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0U2luZ2xlVGFibGUoJHN0YXRlUGFyYW1zLmRiTmFtZSwgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSlcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHRoZVRhYmxlKSB7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHRoZVRhYmxlWzBdO1xuICAgICAgICAgICAgICAgICAgICBDcmVhdGVDb2x1bW5zKCk7XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdmFyIG5leHRDb2xOdW0gPSAkc2NvcGUuY29sdW1ucy5sZW5ndGggKyAxO1xuICAgICAgICAgICAgdmFyIG5ld0NvbE5hbWUgPSAnQ29sdW1uICcgKyBuZXh0Q29sTnVtO1xuICAgICAgICAgICAgVGFibGVGYWN0b3J5LmFkZENvbHVtbihkYiwgdGFibGUsICdDb2x1bW4gMScpXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0U2luZ2xlVGFibGUoJHN0YXRlUGFyYW1zLmRiTmFtZSwgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSlcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHRoZVRhYmxlKSB7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHRoZVRhYmxlWzBdO1xuICAgICAgICAgICAgICAgICAgICBDcmVhdGVDb2x1bW5zKCk7XG4gICAgICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICB9XG5cbiAgICB9XG5cbiAgICAvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vT3JnYW5pemluZyBzdHVmZiBpbnRvIGFycmF5cy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgIC8vIEdldCBhbGwgb2YgdGhlIGNvbHVtbnMgdG8gY3JlYXRlIHRoZSBjb2x1bW5zIG9uIHRoZSBib290c3RyYXAgdGFibGVcblxuICAgIGZ1bmN0aW9uIENyZWF0ZUNvbHVtbnMoKSB7XG4gICAgICAgICRzY29wZS5jb2x1bW5zID0gW107XG4gICAgICAgICRzY29wZS5vcmlnaW5hbENvbFZhbHMgPSBbXTtcbiAgICAgICAgdmFyIHRhYmxlID0gJHNjb3BlLnNpbmdsZVRhYmxlWzBdO1xuXG5cbiAgICAgICAgZm9yICh2YXIgcHJvcCBpbiB0YWJsZSkge1xuICAgICAgICAgICAgaWYgKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuY29sdW1ucy5wdXNoKHByb3ApO1xuICAgICAgICAgICAgICAgICRzY29wZS5vcmlnaW5hbENvbFZhbHMucHVzaChwcm9wKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cblxuICAgIENyZWF0ZUNvbHVtbnMoKTtcblxuICAgIGZ1bmN0aW9uIGNyZWF0ZVZpcnR1YWxDb2x1bW5zKCkge1xuICAgICAgICBpZiAoJHNjb3BlLmFzc29jaWF0aW9ucy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAkc2NvcGUudmlydHVhbENvbHVtbnMgPSBbXTtcbiAgICAgICAgICAgICRzY29wZS5hc3NvY2lhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgICAgICBpZiAocm93LlRhYmxlMSA9PT0gJHNjb3BlLnRoZVRhYmxlTmFtZSAmJiByb3cuUmVsYXRpb25zaGlwMSA9PT0gJ2hhc01hbnknKSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciB2aXJ0dWFsID0ge307XG4gICAgICAgICAgICAgICAgICAgIHZpcnR1YWwubmFtZSA9IHJvdy5BbGlhczE7XG4gICAgICAgICAgICAgICAgICAgIGlmIChyb3cuVGhyb3VnaCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC50YWJsZSA9IHJvdy5UaHJvdWdoO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5jb2x1bW5rZXkgPSByb3cuQWxpYXMxO1xuICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC50YWJsZSA9IHJvdy5UYWJsZTI7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLmNvbHVtbmtleSA9IHJvdy5BbGlhczI7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnZpcnR1YWxDb2x1bW5zLnB1c2godmlydHVhbCk7XG4gICAgICAgICAgICAgICAgfSBlbHNlIGlmIChyb3cuVGFibGUyID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmIHJvdy5SZWxhdGlvbnNoaXAyID09PSAnaGFzTWFueScpIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHZpcnR1YWwgPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5uYW1lID0gcm93LkFsaWFzMjtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHJvdy5UaHJvdWdoKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLnRhYmxlID0gcm93LlRocm91Z2g7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLmNvbHVtbmtleSA9IHJvdy5BbGlhczI7XG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLnRhYmxlID0gcm93LlRhYmxlMTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwuY29sdW1ua2V5ID0gcm93LkFsaWFzMTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAkc2NvcGUudmlydHVhbENvbHVtbnMucHVzaCh2aXJ0dWFsKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgY3JlYXRlVmlydHVhbENvbHVtbnMoKTtcblxuICAgIC8vdGhpcyBmdW5jdGlvbiB3aWxsIHJlIHJ1biB3aGVuIHRoZSBmaWx0ZXIgZnVuY3Rpb24gaXMgaW52b2tlZCwgaW4gb3JkZXIgdG8gcmVwb3B1bGF0ZSB0aGUgdGFibGVcbiAgICBmdW5jdGlvbiBDcmVhdGVSb3dzKCkge1xuICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheSA9IFtdO1xuICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIHZhciByb3dWYWx1ZXMgPSBbXTtcbiAgICAgICAgICAgIHZhciByb3dPYmogPSB7fTtcblxuICAgICAgICAgICAgZm9yICh2YXIgcHJvcCBpbiByb3cpIHtcbiAgICAgICAgICAgICAgICBpZiAocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jykgcm93VmFsdWVzLnB1c2goe1xuICAgICAgICAgICAgICAgICAgICBjb2w6IHByb3AsXG4gICAgICAgICAgICAgICAgICAgIHZhbHVlOiByb3dbcHJvcF1cbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcm93T2JqLnZhbHVlcyA9IHJvd1ZhbHVlcztcbiAgICAgICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5LnB1c2gocm93T2JqKTtcbiAgICAgICAgfSlcbiAgICB9XG5cbiAgICAvLyBTb3J0IHRoZSB2YWx1ZXMgaW4gc2luZ2xlVGFibGUgc28gdGhhdCBhbGwgdGhlIHZhbHVlcyBmb3IgYSBnaXZlbiByb3cgYXJlIGdyb3VwZWRcbiAgICBDcmVhdGVSb3dzKCk7XG4gICAgLy9zZW5kcyB0aGUgZmlsdGVyaW5nIHF1ZXJ5IGFuZCB0aGVuIHJlIHJlbmRlcnMgdGhlIHRhYmxlIHdpdGggZmlsdGVyZWQgZGF0YVxuICAgICRzY29wZS5maWx0ZXIgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgZGF0YSkge1xuICAgICAgICBUYWJsZUZhY3RvcnkuZmlsdGVyKGRiTmFtZSwgdGFibGVOYW1lLCBkYXRhKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0LmRhdGE7XG4gICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgfSlcbiAgICB9XG5cblxuICAgICRzY29wZS5jaGVja0ZvcmVpZ24gPSBmdW5jdGlvbihjb2wpIHtcbiAgICAgICAgcmV0dXJuICRzY29wZS5mb3JlaWduQ29scy5oYXNPd25Qcm9wZXJ0eShjb2wpO1xuICAgIH1cblxuICAgICRzY29wZS5maW5kUHJpbWFyeSA9IFRhYmxlRmFjdG9yeS5maW5kUHJpbWFyeTtcblxuICAgIC8vKioqKioqKioqKioqIEltcG9ydGFudCAqKioqKioqKipcbiAgICAvLyBNYWtlIHN1cmUgdG8gdXBkYXRlIHRoZSByb3cgdmFsdWVzIEJFRk9SRSB0aGUgY29sdW1uIG5hbWVcbiAgICAvLyBUaGUgcm93VmFsc1RvVXBkYXRlIGFycmF5IHN0b3JlcyB0aGUgdmFsdWVzIG9mIHRoZSBPUklHSU5BTCBjb2x1bW4gbmFtZXMgc28gaWYgdGhlIGNvbHVtbiBuYW1lIGlzIHVwZGF0ZWQgYWZ0ZXIgdGhlIHJvdyB2YWx1ZSwgd2Ugc3RpbGwgaGF2ZSByZWZlcmVuY2UgdG8gd2hpY2ggY29sdW1uIHRoZSByb3cgdmFsdWUgcmVmZXJlbmNlc1xuXG5cbiAgICAvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vVXBkYXRpbmcgQ29sdW1uIFN0dWZmLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuXG4gICAgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZSA9IFtdO1xuXG4gICAgJHNjb3BlLnVwZGF0ZUNvbHVtbnMgPSBmdW5jdGlvbihvbGQsIG5ld0NvbE5hbWUsIGkpIHtcbiAgICAgICAgJHNjb3BlLmNvbHVtbnNbaV0gPSBuZXdDb2xOYW1lO1xuXG4gICAgICAgIHZhciBjb2xPYmogPSB7IG9sZFZhbDogJHNjb3BlLm9yaWdpbmFsQ29sVmFsc1tpXSwgbmV3VmFsOiBuZXdDb2xOYW1lIH07XG5cbiAgICAgICAgLy8gaWYgdGhlcmUgaXMgbm90aGluZyBpbiB0aGUgYXJyYXkgdG8gdXBkYXRlLCBwdXNoIHRoZSB1cGRhdGUgaW50byBpdFxuICAgICAgICBpZiAoJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZS5sZW5ndGggPT09IDApIHsgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZS5wdXNoKGNvbE9iaik7IH0gZWxzZSB7XG4gICAgICAgICAgICBmb3IgKHZhciBlID0gMDsgZSA8ICRzY29wZS5jb2xWYWxzVG9VcGRhdGUubGVuZ3RoOyBlKyspIHtcbiAgICAgICAgICAgICAgICBpZiAoJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZVtlXS5vbGRWYWwgPT09IGNvbE9iai5vbGRWYWwpIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZVtlXSA9IGNvbE9iajtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgICRzY29wZS5jb2xWYWxzVG9VcGRhdGUucHVzaChjb2xPYmopO1xuICAgICAgICB9XG4gICAgICAgIC8vIGNoZWNrIHRvIHNlZSBpZiB0aGUgcm93IGlzIGFscmVhZHkgc2NoZWR1bGVkIHRvIGJlIHVwZGF0ZWQsIGlmIGl0IGlzLCB0aGVuIHVwZGF0ZSBpdCB3aXRoIHRoZSBuZXcgdGhpbmcgdG8gYmUgdXBkYXRlZFxuICAgIH1cblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9VcGRhdGluZyBSb3cgU3R1ZmYvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG5cbiAgICAkc2NvcGUucm93VmFsc1RvVXBkYXRlID0gW107XG5cbiAgICAkc2NvcGUudXBkYXRlUm93ID0gZnVuY3Rpb24ob2xkLCBuZXdDZWxsLCByb3csIGksIGope1xuICAgICAgICB2YXIgY29scyA9ICRzY29wZS5vcmlnaW5hbENvbFZhbHM7XG4gICAgICAgIHZhciBmb3VuZCA9IGZhbHNlO1xuICAgICAgICB2YXIgY29sTmFtZSA9IGNvbHNbal07XG4gICAgICAgIGZvcih2YXIgayA9IDA7IGsgPCAkc2NvcGUucm93VmFsc1RvVXBkYXRlLmxlbmd0aDsgaysrKXtcbiAgICAgICAgICAgIHZhciBvYmogPSAkc2NvcGUucm93VmFsc1RvVXBkYXRlW2tdO1xuICAgICAgICAgICAgY29uc29sZS5sb2cob2JqKVxuICAgICAgICAgICAgaWYob2JqWydpZCddID09PSBpKXtcbiAgICAgICAgICAgICAgICBmb3VuZCA9IHRydWU7XG4gICAgICAgICAgICAgICAgaWYob2JqW2NvbE5hbWVdKSBvYmpbY29sTmFtZV0gPSBuZXdDZWxsO1xuICAgICAgICAgICAgICAgIG9ialtjb2xOYW1lXSA9IG5ld0NlbGw7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgaWYoIWZvdW5kKSB7XG4gICAgICAgICAgICB2YXIgcm93T2JqID0ge307XG4gICAgICAgICAgICByb3dPYmpbJ2lkJ10gPSBpO1xuICAgICAgICAgICAgcm93T2JqW2NvbE5hbWVdID0gbmV3Q2VsbDtcbiAgICAgICAgICAgICRzY29wZS5yb3dWYWxzVG9VcGRhdGUucHVzaChyb3dPYmopXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAkc2NvcGUudXBkYXRlQmFja2VuZCA9IGZ1bmN0aW9uKCkge1xuICAgICAgICB2YXIgZGF0YSA9IHsgcm93czogJHNjb3BlLnJvd1ZhbHNUb1VwZGF0ZSwgY29sdW1uczogJHNjb3BlLmNvbFZhbHNUb1VwZGF0ZSB9XG4gICAgICAgIFRhYmxlRmFjdG9yeS51cGRhdGVCYWNrZW5kKCRzY29wZS50aGVEYk5hbWUsICRzY29wZS50aGVUYWJsZU5hbWUsIGRhdGEpO1xuICAgIH1cblxuXG4gICAgJHNjb3BlLmRlbGV0ZVRhYmxlID0gZnVuY3Rpb24oKSB7XG4gICAgICAgIFRhYmxlRmFjdG9yeS5kZWxldGVUYWJsZSgkc2NvcGUuY3VycmVudFRhYmxlKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgJHN0YXRlLmdvKCdUYWJsZScsIHsgZGJOYW1lOiAkc2NvcGUudGhlRGJOYW1lIH0sIHsgcmVsb2FkOiB0cnVlIH0pXG4gICAgICAgICAgICB9KVxuICAgIH1cblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9RdWVyeWluZyBTdHVmZi8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMgPSBbXTtcblxuICAgICRzY29wZS50YWJsZXNUb1F1ZXJ5ID0gW107XG5cbiAgICBhc3NvY2lhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgaWYgKHJvdy5UYWJsZTEgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9ucy5pbmRleE9mKHJvdy5UYWJsZTIpID09IC0xKSB7XG4gICAgICAgICAgICAkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zLnB1c2gocm93LlRhYmxlMik7XG4gICAgICAgIH0gZWxzZSBpZiAocm93LlRhYmxlMiA9PT0gJHNjb3BlLnRoZVRhYmxlTmFtZSAmJiAkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zLmluZGV4T2Yocm93LlRhYmxlMSkgPT0gLTEpIHtcbiAgICAgICAgICAgICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMucHVzaChyb3cuVGFibGUxKTtcbiAgICAgICAgfVxuICAgIH0pXG5cbiAgICAkc2NvcGUuZ2V0QXNzb2NpYXRlZCA9IGZ1bmN0aW9uKHZhbCkge1xuICAgICAgICBpZiAoJHNjb3BlLnRhYmxlc1RvUXVlcnkuaW5kZXhPZigkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zW3ZhbF0pID09PSAtMSkge1xuICAgICAgICAgICAgJHNjb3BlLnRhYmxlc1RvUXVlcnkucHVzaCgkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zW3ZhbF0pXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB2YXIgaSA9ICRzY29wZS50YWJsZXNUb1F1ZXJ5LmluZGV4T2YoJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9uc1t2YWxdKTtcbiAgICAgICAgICAgICRzY29wZS50YWJsZXNUb1F1ZXJ5LnNwbGljZShpLCAxKVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLmNvbHVtbnNGb3JRdWVyeSA9IFtdO1xuXG4gICAgJHNjb3BlLmdldENvbHVtbnNGb3JUYWJsZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgICB2YXIgcHJvbWlzZXNGb3JDb2x1bW5zID0gW107XG4gICAgICAgICRzY29wZS50YWJsZXNUb1F1ZXJ5LmZvckVhY2goZnVuY3Rpb24odGFibGVOYW1lKSB7XG4gICAgICAgICAgICByZXR1cm4gcHJvbWlzZXNGb3JDb2x1bW5zLnB1c2goVGFibGVGYWN0b3J5LmdldENvbHVtbnNGb3JUYWJsZSgkc2NvcGUudGhlRGJOYW1lLCB0YWJsZU5hbWUpKVxuICAgICAgICB9KVxuICAgICAgICBQcm9taXNlLmFsbChwcm9taXNlc0ZvckNvbHVtbnMpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihjb2x1bW5zKSB7XG4gICAgICAgICAgICAgICAgY29sdW1ucy5mb3JFYWNoKGZ1bmN0aW9uKGNvbHVtbikge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuY29sdW1uc0ZvclF1ZXJ5LnB1c2goY29sdW1uKTtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLiRldmFsQXN5bmMoKVxuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB9KVxuXG4gICAgfVxuXG4gICAgdmFyIHNlbGVjdGVkQ29sdW1ucyA9IHt9O1xuICAgIHZhciBxdWVyeVRhYmxlO1xuXG4gICAgJHNjb3BlLmdldERhdGFGcm9tQ29sdW1ucyA9IGZ1bmN0aW9uKHZhbCkge1xuICAgICAgICBpZighc2VsZWN0ZWRDb2x1bW5zKSBzZWxlY3RlZENvbHVtbnMgPSBbXTtcblxuICAgICAgICB2YXIgY29sdW1uTmFtZSA9ICRzY29wZS5jb2x1bW5zRm9yUXVlcnlbMF1bJ2NvbHVtbnMnXVt2YWwuaV07XG4gICAgICAgIHZhciB0YWJsZU5hbWUgPSB2YWwudGFibGVOYW1lXG4gICAgICAgIHF1ZXJ5VGFibGUgPSB0YWJsZU5hbWU7XG5cbiAgICAgICAgaWYgKCFzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXSkgc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0gPSBbXTtcbiAgICAgICAgaWYgKHNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdLmluZGV4T2YoY29sdW1uTmFtZSkgIT09IC0xKSB7XG4gICAgICAgICAgICBzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXS5zcGxpY2Uoc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0uaW5kZXhPZihjb2x1bW5OYW1lKSwgMSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdLnB1c2goY29sdW1uTmFtZSk7XG4gICAgICAgIH1cbiAgICAgICAgJHNjb3BlLnNlbGVjdGVkQ29sdW1ucyA9IHNlbGVjdGVkQ29sdW1ucztcbiAgICB9XG5cblxuICAgIC8vIFJ1bm5pbmcgdGhlIHF1ZXJ5ICsgcmVuZGVyaW5nIHRoZSBxdWVyeVxuICAgICRzY29wZS5yZXN1bHRPZlF1ZXJ5ID0gW107XG5cbiAgICAkc2NvcGUucXVlcnlSZXN1bHQ7XG5cbiAgICAkc2NvcGUuYXJyID0gW107XG5cblxuICAgIC8vIHRoZVRhYmxlTmFtZVxuXG4gICAgJHNjb3BlLnJ1bkpvaW4gPSBmdW5jdGlvbigpIHtcbiAgICAgICAgLy8gZGJOYW1lLCB0YWJsZTEsIGFycmF5T2ZUYWJsZXMsIHNlbGVjdGVkQ29sdW1ucywgYXNzb2NpYXRpb25zXG4gICAgICAgIHZhciBjb2x1bW5zVG9SZXR1cm4gPSAkc2NvcGUuY29sdW1ucy5tYXAoZnVuY3Rpb24oY29sTmFtZSl7XG4gICAgICAgICAgICByZXR1cm4gJHNjb3BlLnRoZVRhYmxlTmFtZSArICcuJyArIGNvbE5hbWU7XG4gICAgICAgIH0pXG4gICAgICAgIGZvcih2YXIgcHJvcCBpbiAkc2NvcGUuc2VsZWN0ZWRDb2x1bW5zKXtcbiAgICAgICAgICAgJHNjb3BlLnNlbGVjdGVkQ29sdW1uc1twcm9wXS5mb3JFYWNoKGZ1bmN0aW9uKGNvbCl7XG4gICAgICAgICAgICAgICAgY29sdW1uc1RvUmV0dXJuLnB1c2gocHJvcCArICcuJyArIGNvbClcbiAgICAgICAgICAgfSlcbiAgICAgICAgfVxuICAgICAgICBUYWJsZUZhY3RvcnkucnVuSm9pbigkc2NvcGUudGhlRGJOYW1lLCAkc2NvcGUudGhlVGFibGVOYW1lLCAkc2NvcGUudGFibGVzVG9RdWVyeSwgJHNjb3BlLnNlbGVjdGVkQ29sdW1ucywgJHNjb3BlLmFzc29jaWF0aW9ucywgY29sdW1uc1RvUmV0dXJuKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocXVlcnlSZXN1bHQpIHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmxvZygnUVVFUllSUkVTVUxUJywgcXVlcnlSZXN1bHQpO1xuICAgICAgICAgICAgICAgICRzY29wZS5xdWVyeVJlc3VsdCA9IHF1ZXJ5UmVzdWx0O1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnVGFibGUuU2luZ2xlLnF1ZXJ5Jyk7XG4gICAgICAgICAgICB9KVxuICAgIH1cblxuICAgICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9IHRydWU7XG5cbiAgICAkc2NvcGUub3BlbiA9IGZ1bmN0aW9uIChkYk5hbWUsIHRibE5hbWUsIGNvbCwgaW5kZXgpIHtcblxuICAgICAgdmFyIG1vZGFsSW5zdGFuY2UgPSAkdWliTW9kYWwub3Blbih7XG4gICAgICAgIGFuaW1hdGlvbjogJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL2Fzc29jaWF0aW9uLm1vZGFsLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnQXNzb2NpYXRpb25JbnN0YW5jZUN0cmwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgZm9yZWlnbkNvbHM6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiAkc2NvcGUuZm9yZWlnbkNvbHM7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBmb3JUYWJsZTogZnVuY3Rpb24oVGFibGVGYWN0b3J5KXtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKHRibE5hbWUpXG4gICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmZpbmRQcmltYXJ5KGRiTmFtZSwgdGJsTmFtZSk7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBmb3JUYWJsZU5hbWU6IGZ1bmN0aW9uKCl7XG4gICAgICAgICAgICByZXR1cm4gdGJsTmFtZTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIGN1cnJUYWJsZTogZnVuY3Rpb24oKXtcbiAgICAgICAgICAgIHJldHVybiAkc2NvcGUudGhlVGFibGVOYW1lXG4gICAgICAgICAgfSxcbiAgICAgICAgICBjb2xOYW1lOiBmdW5jdGlvbiAoKXtcbiAgICAgICAgICAgIHJldHVybiBjb2w7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBpZDE6IGZ1bmN0aW9uKCl7XG4gICAgICAgICAgICByZXR1cm4gaW5kZXg7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9KTtcblxuICAgICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKFwiQ0xPU0VEXCIpXG4gICAgICAgICRzY29wZS4kZXZhbEFzeW5jKCk7XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgJHNjb3BlLnRvZ2dsZUFuaW1hdGlvbiA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9ICEkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQ7XG4gICAgfTtcblxufSk7XG4iLCJhcHAuY29udHJvbGxlcignVGFibGVDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgYWxsVGFibGVzLCAkc3RhdGUsIFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zLCAkdWliTW9kYWwsIEhvbWVGYWN0b3J5LCBhc3NvY2lhdGlvbnMsIGFsbENvbHVtbnMpIHtcblxuXHQkc2NvcGUuYWxsVGFibGVzID0gYWxsVGFibGVzO1xuXG5cdCRzY29wZS5jb2x1bW5BcnJheSA9IFtdO1xuXG5cdCRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lXG5cblx0JHNjb3BlLmFzc29jaWF0aW9ucyA9IGFzc29jaWF0aW9ucztcblxuXHQkc2NvcGUuYWxsQ29sdW1ucyA9IGFsbENvbHVtbnM7XG5cblx0JHNjb3BlLmFzc29jaWF0aW9uVGFibGUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lICsgJ19hc3NvYyc7XG5cblx0JHNjb3BlLm51bVRhYmxlcyA9ICRzY29wZS5hbGxUYWJsZXMucm93cy5sZW5ndGg7XG5cblx0JHNjb3BlLmFkZCA9IGZ1bmN0aW9uKCkge1xuXHRcdCRzY29wZS5jb2x1bW5BcnJheS5wdXNoKCcxJyk7XG5cdH1cblxuXHQkc2NvcGUuJHN0YXRlID0gJHN0YXRlOyBcdC8vIHVzZWQgdG8gaGlkZSB0aGUgbGlzdCBvZiBhbGwgdGFibGVzIHdoZW4gaW4gc2luZ2xlIHRhYmxlIHN0YXRlXG5cblx0JHNjb3BlLmFzc29jaWF0aW9uVHlwZXMgPSBbJ2hhc09uZScsICdoYXNNYW55J107XG5cblx0JHNjb3BlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG5cblx0JHNjb3BlLnN1Ym1pdHRlZCA9IGZhbHNlO1xuXG5cdCRzY29wZS5tYWtlQXNzb2NpYXRpb25zID0gZnVuY3Rpb24oYXNzb2NpYXRpb24sIGRiTmFtZSkge1xuXHRcdCRzY29wZS5zdWJtaXR0ZWQgPSB0cnVlO1xuXHRcdFRhYmxlRmFjdG9yeS5tYWtlQXNzb2NpYXRpb25zKGFzc29jaWF0aW9uLCBkYk5hbWUpXG5cdH0gXG5cblx0JHNjb3BlLndoZXJlYmV0d2VlbiA9IGZ1bmN0aW9uKGNvbmRpdGlvbikge1xuXHRcdGlmKGNvbmRpdGlvbiA9PT0gXCJXSEVSRSBCRVRXRUVOXCIgfHwgY29uZGl0aW9uID09PSBcIldIRVJFIE5PVCBCRVRXRUVOXCIpIHJldHVybiB0cnVlO1xuXHR9XG5cblx0JHNjb3BlLmNyZWF0ZVRhYmxlID0gZnVuY3Rpb24odGFibGUpe1xuXHRcdFRhYmxlRmFjdG9yeS5jcmVhdGVUYWJsZSh0YWJsZSlcblx0XHQudGhlbihmdW5jdGlvbigpe1xuXHRcdFx0JHN0YXRlLmdvKCdUYWJsZScsIHtkYk5hbWU6ICRzY29wZS5kYk5hbWV9LCB7cmVsb2FkOiB0cnVlfSk7XG5cdFx0fSlcblx0fVxuXG5cdCRzY29wZS5jb2x1bW5EYXRhVHlwZSA9IGZ1bmN0aW9uKCkge1xuXHRcdCRzY29wZS5hbGxDb2x1bW5zLmZvckVhY2goZnVuY3Rpb24ob2JqKSB7XG5cdFx0XHRpZihvYmoudGFibGVfbmFtZSA9PT0gJHNjb3BlLnF1ZXJ5LnRhYmxlMSAmJiBvYmouY29sdW1uX25hbWUgPT09ICRzY29wZS5xdWVyeS5jb2x1bW4pICRzY29wZS50eXBlID0gb2JqLmRhdGFfdHlwZTtcblx0XHR9KVxuXHR9XG5cblx0JHNjb3BlLnNlbGVjdGVkQXNzb2MgPSB7fTtcblxuXHQkc2NvcGUuc3VibWl0UXVlcnkgPSBUYWJsZUZhY3Rvcnkuc3VibWl0UXVlcnk7XG5cbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ1RhYmxlRmFjdG9yeScsIGZ1bmN0aW9uICgkaHR0cCwgJHN0YXRlUGFyYW1zKSB7XG5cblx0dmFyIFRhYmxlRmFjdG9yeSA9IHt9O1xuXG5cdGZ1bmN0aW9uIHJlc1RvRGF0YShyZXMpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5kYXRhO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRBbGxUYWJsZXMgPSBmdW5jdGlvbihkYk5hbWUpe1xuICAgIFx0cmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lKVxuICAgIFx0LnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldERiTmFtZSA9IGZ1bmN0aW9uKGRiTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvbWFzdGVyZGIvJyArIGRiTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5maWx0ZXIgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgZGF0YSkge1xuICAgICAgICByZXR1cm4gJGh0dHAucHV0KCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnL2ZpbHRlcicsIGRhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LnVwZGF0ZUJhY2tlbmQgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgZGF0YSkge1xuICAgICAgICByZXR1cm4gJGh0dHAucHV0KCdhcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSwgZGF0YSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuYWRkUm93ID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIHJvd051bWJlcikge1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnYXBpL2NsaWVudGRiL2FkZHJvdy8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lLCB7cm93TnVtYmVyOiByb3dOdW1iZXJ9KVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVSb3cgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgcm93SWQpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnLycgKyByb3dJZClcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVDb2x1bW4gPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgY29sdW1uTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSArICcvY29sdW1uLycgKyBjb2x1bW5OYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmFkZENvbHVtbiA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCBudW1OZXdDb2wpe1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnYXBpL2NsaWVudGRiL2FkZGNvbHVtbi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lICsgJy8nICsgbnVtTmV3Q29sKVxuICAgIH1cbiAgICBUYWJsZUZhY3RvcnkuY3JlYXRlVGFibGUgPSBmdW5jdGlvbih0YWJsZSl7XG4gICAgICAgIHRhYmxlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG4gICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL2NsaWVudGRiJywgdGFibGUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmRlbGV0ZVRhYmxlID0gZnVuY3Rpb24oY3VycmVudFRhYmxlKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvY2xpZW50ZGIvJyArIGN1cnJlbnRUYWJsZS5kYk5hbWUgKyAnLycgKyBjdXJyZW50VGFibGUudGFibGVOYW1lKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5tYWtlQXNzb2NpYXRpb25zID0gZnVuY3Rpb24oYXNzb2NpYXRpb24sIGRiTmFtZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy9hc3NvY2lhdGlvbicsIGFzc29jaWF0aW9uKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5kZWxldGVEYiA9IGZ1bmN0aW9uKGRiTmFtZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldEFzc29jaWF0aW9ucyA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvYXNzb2NpYXRpb250YWJsZS8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgICBUYWJsZUZhY3RvcnkuZ2V0QWxsQXNzb2NpYXRpb25zID0gZnVuY3Rpb24oZGJOYW1lKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvYWxsYXNzb2NpYXRpb25zLycgKyBkYk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldEFsbENvbHVtbnMgPSBmdW5jdGlvbihkYk5hbWUpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi9nZXRhbGxjb2x1bW5zLycgKyBkYk5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldENvbHVtbnNGb3JUYWJsZSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi9jb2x1bW5zZm9ydGFibGUvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkucnVuSm9pbiA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGUxLCBhcnJheU9mVGFibGVzLCBzZWxlY3RlZENvbHVtbnMsIGFzc29jaWF0aW9ucywgY29sc1RvUmV0dXJuKSB7XG4gICAgICAgIHZhciBkYXRhID0ge307XG4gICAgICAgIGRhdGEuZGJOYW1lID0gZGJOYW1lO1xuICAgICAgICBkYXRhLnRhYmxlMiA9IGFycmF5T2ZUYWJsZXNbMF07XG4gICAgICAgIGRhdGEuYXJyYXlPZlRhYmxlcyA9IGFycmF5T2ZUYWJsZXM7XG4gICAgICAgIGRhdGEuc2VsZWN0ZWRDb2x1bW5zID0gc2VsZWN0ZWRDb2x1bW5zO1xuICAgICAgICBkYXRhLmNvbHNUb1JldHVybiA9IGNvbHNUb1JldHVybjtcblxuICAgICAgICAvLyBbaGFzTWFueSwgaGFzT25lLCBoYXNNYW55IHByaW1hcnkga2V5LCBoYXNPbmUgZm9yZ2VpbiBrZXldXG5cbiAgICAgICAgYXNzb2NpYXRpb25zLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICBpZihyb3cuVGFibGUxID09PSB0YWJsZTEgJiYgcm93LlRhYmxlMiA9PT0gZGF0YS50YWJsZTIpe1xuICAgICAgICAgICAgICAgIGRhdGEuYWxpYXMgPSByb3cuQWxpYXMxO1xuICAgICAgICAgICAgICAgIGlmKHJvdy5SZWxhdGlvbnNoaXAxID09PSAnaGFzT25lJyl7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUxID0gcm93LlRhYmxlMjtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTIgPSByb3cuVGFibGUxO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNle1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMSA9IHJvdy5UYWJsZTE7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUyID0gcm93LlRhYmxlMjsgICBcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIGlmKHJvdy5UYWJsZTEgPT09IGRhdGEudGFibGUyICYmIHJvdy5UYWJsZTIgPT09IHRhYmxlMSl7XG4gICAgICAgICAgICAgICAgZGF0YS5hbGlhcyA9IHJvdy5BbGlhczE7XG4gICAgICAgICAgICAgICAgaWYocm93LlJlbGF0aW9uc2hpcDEgPT09ICdoYXNNYW55Jyl7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUxID0gcm93LlRhYmxlMTtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTIgPSByb3cuVGFibGUyO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNle1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMSA9IHJvdy5UYWJsZTI7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUyID0gcm93LlRhYmxlMTsgICBcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pXG5cbiAgICAgICAgY29uc29sZS5sb2coJ0RBVEEnLGRhdGEpO1xuXG4gICAgICAgIHJldHVybiAkaHR0cC5wdXQoJy9hcGkvY2xpZW50ZGIvcnVuam9pbicsIGRhdGEpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldFByaW1hcnlLZXlzID0gZnVuY3Rpb24oaWQsIGRiTmFtZSwgdGFibGVOYW1lLCBjb2x1bW5rZXkpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnLycgKyBpZCArIFwiL1wiICsgY29sdW1ua2V5KVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5maW5kUHJpbWFyeSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGJsTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvcHJpbWFyeS8nK2RiTmFtZSsnLycrdGJsTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3Rvcnkuc2V0Rm9yZWlnbktleSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGJsTmFtZSwgY29sTmFtZSwgaWQxLCBpZDIpe1xuICAgICAgICB2YXIgZGF0YSA9IHt9O1xuICAgICAgICBkYXRhLmRiTmFtZSA9IGRiTmFtZTtcbiAgICAgICAgZGF0YS50YmxOYW1lID0gdGJsTmFtZTtcbiAgICAgICAgZGF0YS5jb2xOYW1lID0gY29sTmFtZTtcbiAgICAgICAgZGF0YS5pZDEgPSBpZDE7XG4gICAgICAgIGRhdGEuaWQyID0gaWQyO1xuXG4gICAgICAgIHJldHVybiAkaHR0cC5wdXQoJy9hcGkvY2xpZW50ZGIvc2V0Rm9yZWlnbktleScsIGRhdGEpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7ICAgXG4gICAgfVxuXG5cdHJldHVybiBUYWJsZUZhY3Rvcnk7IFxufSkiLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZScsIHtcbiAgICAgICAgdXJsOiAnLzpkYk5hbWUnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL3RhYmxlLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVGFibGVDdHJsJyxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICBcdGFsbFRhYmxlczogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldEFsbFRhYmxlcygkc3RhdGVQYXJhbXMuZGJOYW1lKTtcbiAgICAgICAgXHR9LCBcbiAgICAgICAgICAgIGFzc29jaWF0aW9uczogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldEFsbEFzc29jaWF0aW9ucygkc3RhdGVQYXJhbXMuZGJOYW1lKTtcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBhbGxDb2x1bW5zOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0QWxsQ29sdW1ucygkc3RhdGVQYXJhbXMuZGJOYW1lKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pO1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlLlNpbmdsZScsIHtcbiAgICAgICAgdXJsOiAnLzp0YWJsZU5hbWUnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL3NpbmdsZXRhYmxlLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnU2luZ2xlVGFibGVDdHJsJyxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICAgICAgc2luZ2xlVGFibGU6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSgkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKTtcbiAgICAgICAgICAgIH0sIFxuICAgICAgICAgICAgYXNzb2NpYXRpb25zOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0QXNzb2NpYXRpb25zKCRzdGF0ZVBhcmFtcy5kYk5hbWUsICRzdGF0ZVBhcmFtcy50YWJsZU5hbWUpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSk7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUuSm9pbicsIHtcbiAgICAgICAgdXJsOiAnLzp0YWJsZU5hbWUvOnJvd0lkLzprZXkvam9pbicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvam9pbi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0pvaW5UYWJsZUN0cmwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgICBqb2luVGFibGU6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRQcmltYXJ5S2V5cygkc3RhdGVQYXJhbXMucm93SWQsICRzdGF0ZVBhcmFtcy5kYk5hbWUsICRzdGF0ZVBhcmFtcy50YWJsZU5hbWUsICRzdGF0ZVBhcmFtcy5rZXkpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSk7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUuVGhyb3VnaCcsIHtcbiAgICAgICAgdXJsOiAnLzp0YWJsZU5hbWUvdGhyb3VnaCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvdGhyb3VnaC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Rocm91Z2hDdHJsJywgXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICAgIHNpbmdsZVRhYmxlOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0U2luZ2xlVGFibGUoJHN0YXRlUGFyYW1zLmRiTmFtZSwgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KTsgIFxuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlLmNyZWF0ZScsIHtcbiAgICAgICAgdXJsOiAnL2NyZWF0ZXRhYmxlJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9jcmVhdGV0YWJsZS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1RhYmxlQ3RybCdcbiAgICB9KTtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5zZXRBc3NvY2lhdGlvbicsIHtcbiAgICAgICAgdXJsOiAnL3NldGFzc29jaWF0aW9uJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9zZXRhc3NvY2lhdGlvbi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1RhYmxlQ3RybCdcbiAgICB9KTtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5TaW5nbGUucXVlcnknLCB7XG4gICAgICAgIHVybDogJy9xdWVyeXJlc3VsdCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvcXVlcnkuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdRdWVyeVRhYmxlQ3RybCdcbiAgICB9KTsgICAgIFxuXG5cbn0pOyIsImFwcC5jb250cm9sbGVyKCdUaHJvdWdoQ3RybCcsIGZ1bmN0aW9uKCRzY29wZSwgVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMsIGFzc29jaWF0aW9ucywgc2luZ2xlVGFibGUsICR1aWJNb2RhbCkge1xuXG4gICAgJHNjb3BlLmFzc29jaWF0aW9ucyA9IGFzc29jaWF0aW9ucztcbiAgICAkc2NvcGUudHdvVGFibGVzID0gW107XG4gICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gc2luZ2xlVGFibGVbMF07XG4gICAgJHNjb3BlLnRoZURiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG4gICAgJHNjb3BlLnRhYmxlTmFtZSA9ICRzdGF0ZVBhcmFtcy50YWJsZU5hbWU7XG5cbiAgICBmdW5jdGlvbiBnZXQyVGFibGVzKCkge1xuICAgICAgICAkc2NvcGUuYXNzb2NpYXRpb25zLmZvckVhY2goZnVuY3Rpb24oYXNzb2MpIHtcbiAgICAgICAgICAgIGlmIChhc3NvY1snVGhyb3VnaCddID09PSAkc3RhdGVQYXJhbXMudGFibGVOYW1lKSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnR3b1RhYmxlcy5wdXNoKGFzc29jWydUYWJsZTEnXSk7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnR3b1RhYmxlcy5wdXNoKGFzc29jWydUYWJsZTInXSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pXG4gICAgfVxuXG4gICAgZ2V0MlRhYmxlcygpO1xuXG4gICAgZnVuY3Rpb24gQ3JlYXRlQ29sdW1ucygpIHtcbiAgICAgICAgJHNjb3BlLmNvbHVtbnMgPSBbXTtcbiAgICAgICAgdmFyIHRhYmxlID0gc2luZ2xlVGFibGVbMF1bMF07XG4gICAgICAgIGZvciAodmFyIHByb3AgaW4gdGFibGUpIHtcbiAgICAgICAgICAgICRzY29wZS5jb2x1bW5zLnB1c2gocHJvcCk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBDcmVhdGVDb2x1bW5zKCk7XG5cblxuICAgIC8vdGhpcyBmdW5jdGlvbiB3aWxsIHJlIHJ1biB3aGVuIHRoZSBmaWx0ZXIgZnVuY3Rpb24gaXMgaW52b2tlZCwgaW4gb3JkZXIgdG8gcmVwb3B1bGF0ZSB0aGUgdGFibGVcbiAgICBmdW5jdGlvbiBDcmVhdGVSb3dzKCkge1xuICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheSA9IFtdO1xuICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIHZhciByb3dWYWx1ZXMgPSBbXTtcbiAgICAgICAgICAgIGZvciAodmFyIHByb3AgaW4gcm93KSB7XG4gICAgICAgICAgICAgICAgcm93VmFsdWVzLnB1c2gocm93W3Byb3BdKVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkucHVzaChyb3dWYWx1ZXMpXG4gICAgICAgIH0pXG4gICAgfVxuXG4gICAgLy8gU29ydCB0aGUgdmFsdWVzIGluIHNpbmdsZVRhYmxlIHNvIHRoYXQgYWxsIHRoZSB2YWx1ZXMgZm9yIGEgZ2l2ZW4gcm93IGFyZSBncm91cGVkXG4gICAgQ3JlYXRlUm93cygpO1xuXG4gICAgLy8gJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkID0gdHJ1ZTtcblxuICAgICRzY29wZS5vcGVuID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIGluZGV4KSB7XG4gICAgICAgIHZhciB0aGVUYWJsZSA9ICRzY29wZS50d29UYWJsZXNbaW5kZXhdO1xuXG4gICAgICAgIHZhciBtb2RhbEluc3RhbmNlID0gJHVpYk1vZGFsLm9wZW4oe1xuICAgICAgICAgICAgYW5pbWF0aW9uOiAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQsXG4gICAgICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL3Rocm91Z2gubW9kYWwuaHRtbCcsXG4gICAgICAgICAgICBjb250cm9sbGVyOiAnVGhyb3VnaE1vZGFsQ3RybCcsXG4gICAgICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgICAgICAgdGhlVGFibGU6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldFNpbmdsZVRhYmxlKGRiTmFtZSwgdGhlVGFibGUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG5cbiAgICAgICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiQ0xPU0VEXCIpXG4gICAgICAgICAgICAkc2NvcGUuJGV2YWxBc3luYygpO1xuICAgICAgICB9KTtcbiAgICB9O1xuXG4gICAgJHNjb3BlLnRvZ2dsZUFuaW1hdGlvbiA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQgPSAhJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkO1xuICAgIH07XG59KVxuIiwiYXBwLmNvbnRyb2xsZXIoJ1Rocm91Z2hNb2RhbEN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCAkdWliTW9kYWxJbnN0YW5jZSwgVGFibGVGYWN0b3J5LCBIb21lRmFjdG9yeSwgJHN0YXRlUGFyYW1zLCAkc3RhdGUsIHRoZVRhYmxlKSB7XG5cbiAgJHNjb3BlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG5cbiAgJHNjb3BlLnNpbmdsZVRhYmxlID0gdGhlVGFibGU7XG5cbiAgXG5cbiAgJHNjb3BlLnNldFNlbGVjdGVkID0gZnVuY3Rpb24oKXtcblxuICAgICRzY29wZS5jdXJyUm93ID0gdGhpcy5yb3c7XG4gICAgY29uc29sZS5sb2coJHNjb3BlLmN1cnJSb3cpO1xuICB9XG5cbiBcblxuICBmdW5jdGlvbiBDcmVhdGVDb2x1bW5zKCl7XG4gICAgJHNjb3BlLmNvbHVtbnMgPSBbXTtcbiAgICB2YXIgdGFibGUgPSAkc2NvcGUuc2luZ2xlVGFibGVbMF07XG5cblxuICAgIGZvcih2YXIgcHJvcCBpbiB0YWJsZSl7XG4gICAgICBpZihwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKXtcbiAgICAgICAgJHNjb3BlLmNvbHVtbnMucHVzaChwcm9wKTsgIFxuICAgICAgfSBcbiAgICB9XG4gIH1cblxuICAgIENyZWF0ZUNvbHVtbnMoKTtcblxuXG4gICAgLy90aGlzIGZ1bmN0aW9uIHdpbGwgcmUgcnVuIHdoZW4gdGhlIGZpbHRlciBmdW5jdGlvbiBpcyBpbnZva2VkLCBpbiBvcmRlciB0byByZXBvcHVsYXRlIHRoZSB0YWJsZVxuICAgIGZ1bmN0aW9uIENyZWF0ZVJvd3MoKSB7XG4gICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5ID0gW107XG4gICAgICAgICRzY29wZS5zaW5nbGVUYWJsZVswXS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgdmFyIHJvd1ZhbHVlcyA9IFtdO1xuICAgICAgICAgICAgZm9yICh2YXIgcHJvcCBpbiByb3cpIHtcbiAgICAgICAgICAgICAgICBpZiAocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jykgcm93VmFsdWVzLnB1c2gocm93W3Byb3BdKVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkucHVzaChyb3dWYWx1ZXMpXG4gICAgICAgIH0pXG4gICAgfVxuXG4gICAgLy8gU29ydCB0aGUgdmFsdWVzIGluIHNpbmdsZVRhYmxlIHNvIHRoYXQgYWxsIHRoZSB2YWx1ZXMgZm9yIGEgZ2l2ZW4gcm93IGFyZSBncm91cGVkXG4gICAgQ3JlYXRlUm93cygpO1xuXG5cbiAgJHNjb3BlLnNldEZvcmVpZ25LZXkgPSBmdW5jdGlvbihkYk5hbWUsIHRibE5hbWUsIGNvbE5hbWUsIGlkMSwgaWQyKXtcbiAgICAkdWliTW9kYWxJbnN0YW5jZS5jbG9zZSgpO1xuICAgIFRhYmxlRmFjdG9yeS5zZXRGb3JlaWduS2V5KGRiTmFtZSwgdGJsTmFtZSwgY29sTmFtZSwgaWQxLCBpZDIpXG4gICAgLnRoZW4oZnVuY3Rpb24oKXtcbiAgICAgICAgJHN0YXRlLmdvKCdUYWJsZS5TaW5nbGUnLCB7IGRiTmFtZTogJHNjb3BlLmRiTmFtZSwgdGFibGVOYW1lOiAkc2NvcGUuc2luZ2xlVGFibGUgfSwgeyByZWxvYWQ6IHRydWUgfSlcbiAgICB9KVxuICB9XG5cblxuXG4gICRzY29wZS5vayA9IGZ1bmN0aW9uICgpIHtcbiAgICAkdWliTW9kYWxJbnN0YW5jZS5jbG9zZSgkc2NvcGUuc2VsZWN0ZWQuaXRlbSk7XG4gIH07XG5cbiAgJHNjb3BlLmNhbmNlbCA9IGZ1bmN0aW9uICgpIHtcbiAgICAkdWliTW9kYWxJbnN0YW5jZS5kaXNtaXNzKCdjYW5jZWwnKTtcbiAgfTtcbn0pOyIsImFwcC5mYWN0b3J5KCdGdWxsc3RhY2tQaWNzJywgZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiBbXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQjdnQlh1bENBQUFYUWNFLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL2ZiY2RuLXNwaG90b3MtYy1hLmFrYW1haWhkLm5ldC9ocGhvdG9zLWFrLXhhcDEvdDMxLjAtOC8xMDg2MjQ1MV8xMDIwNTYyMjk5MDM1OTI0MV84MDI3MTY4ODQzMzEyODQxMTM3X28uanBnJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CLUxLVXNoSWdBRXk5U0suanBnJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CNzktWDdvQ01BQWt3N3kuanBnJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CLVVqOUNPSUlBSUZBaDAuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CNnlJeUZpQ0VBQXFsMTIuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DRS1UNzVsV0FBQW1xcUouanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DRXZaQWctVkFBQWs5MzIuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DRWdOTWVPWElBSWZEaEsuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DRVF5SUROV2dBQXU2MEIuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DQ0YzVDVRVzhBRTJsR0ouanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DQWVWdzVTV29BQUFMc2ouanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DQWFKSVA3VWtBQWxJR3MuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DQVFPdzlsV0VBQVk5RmwuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CLU9RYlZyQ01BQU53SU0uanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9COWJfZXJ3Q1lBQXdSY0oucG5nOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CNVBUZHZuQ2NBRUFsNHguanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CNHF3QzBpQ1lBQWxQR2guanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CMmIzM3ZSSVVBQTlvMUQuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9Cd3BJd3IxSVVBQXZPMl8uanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9Cc1NzZUFOQ1lBRU9oTHcuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DSjR2TGZ1VXdBQWRhNEwuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DSTd3empFVkVBQU9QcFMuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DSWRIdlQyVXNBQW5uSFYuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DR0NpUF9ZV1lBQW83NVYuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DSVM0SlBJV0lBSTM3cXUuanBnOmxhcmdlJ1xuICAgIF07XG59KTtcbiIsImFwcC5mYWN0b3J5KCdSYW5kb21HcmVldGluZ3MnLCBmdW5jdGlvbiAoKSB7XG5cbiAgICB2YXIgZ2V0UmFuZG9tRnJvbUFycmF5ID0gZnVuY3Rpb24gKGFycikge1xuICAgICAgICByZXR1cm4gYXJyW01hdGguZmxvb3IoTWF0aC5yYW5kb20oKSAqIGFyci5sZW5ndGgpXTtcbiAgICB9O1xuXG4gICAgdmFyIGdyZWV0aW5ncyA9IFtcbiAgICAgICAgJ0hlbGxvLCB3b3JsZCEnLFxuICAgICAgICAnQXQgbG9uZyBsYXN0LCBJIGxpdmUhJyxcbiAgICAgICAgJ0hlbGxvLCBzaW1wbGUgaHVtYW4uJyxcbiAgICAgICAgJ1doYXQgYSBiZWF1dGlmdWwgZGF5IScsXG4gICAgICAgICdJXFwnbSBsaWtlIGFueSBvdGhlciBwcm9qZWN0LCBleGNlcHQgdGhhdCBJIGFtIHlvdXJzLiA6KScsXG4gICAgICAgICdUaGlzIGVtcHR5IHN0cmluZyBpcyBmb3IgTGluZHNheSBMZXZpbmUuJyxcbiAgICAgICAgJ+OBk+OCk+OBq+OBoeOBr+OAgeODpuODvOOCtuODvOanmOOAgicsXG4gICAgICAgICdXZWxjb21lLiBUby4gV0VCU0lURS4nLFxuICAgICAgICAnOkQnLFxuICAgICAgICAnWWVzLCBJIHRoaW5rIHdlXFwndmUgbWV0IGJlZm9yZS4nLFxuICAgICAgICAnR2ltbWUgMyBtaW5zLi4uIEkganVzdCBncmFiYmVkIHRoaXMgcmVhbGx5IGRvcGUgZnJpdHRhdGEnLFxuICAgICAgICAnSWYgQ29vcGVyIGNvdWxkIG9mZmVyIG9ubHkgb25lIHBpZWNlIG9mIGFkdmljZSwgaXQgd291bGQgYmUgdG8gbmV2U1FVSVJSRUwhJyxcbiAgICBdO1xuXG4gICAgcmV0dXJuIHtcbiAgICAgICAgZ3JlZXRpbmdzOiBncmVldGluZ3MsXG4gICAgICAgIGdldFJhbmRvbUdyZWV0aW5nOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gZ2V0UmFuZG9tRnJvbUFycmF5KGdyZWV0aW5ncyk7XG4gICAgICAgIH1cbiAgICB9O1xuXG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ2Z1bGxzdGFja0xvZ28nLCBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIHtcbiAgICAgICAgcmVzdHJpY3Q6ICdFJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9mdWxsc3RhY2stbG9nby9mdWxsc3RhY2stbG9nby5odG1sJ1xuICAgIH07XG59KTsiLCJhcHAuZGlyZWN0aXZlKCdzaWRlYmFyJywgZnVuY3Rpb24gKCRyb290U2NvcGUsIEF1dGhTZXJ2aWNlLCBBVVRIX0VWRU5UUywgJHN0YXRlKSB7XG5cbiAgICByZXR1cm4ge1xuICAgICAgICByZXN0cmljdDogJ0UnLFxuICAgICAgICBzY29wZToge30sXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvY29tbW9uL2RpcmVjdGl2ZXMvbmF2YmFyL25hdmJhci5odG1sJyxcbiAgICAgICAgbGluazogZnVuY3Rpb24gKHNjb3BlKSB7XG5cbiAgICAgICAgICAgIHNjb3BlLml0ZW1zID0gW1xuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdIb21lJywgc3RhdGU6ICdob21lJyB9LFxuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdBYm91dCcsIHN0YXRlOiAnYWJvdXQnIH0sXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ0RvY3VtZW50YXRpb24nLCBzdGF0ZTogJ2RvY3MnIH0sXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ01lbWJlcnMgT25seScsIHN0YXRlOiAnbWVtYmVyc09ubHknLCBhdXRoOiB0cnVlIH1cbiAgICAgICAgICAgIF07XG5cbiAgICAgICAgICAgIHNjb3BlLnVzZXIgPSBudWxsO1xuXG4gICAgICAgICAgICBzY29wZS5pc0xvZ2dlZEluID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBBdXRoU2VydmljZS5pc0F1dGhlbnRpY2F0ZWQoKTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHNjb3BlLmxvZ291dCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBBdXRoU2VydmljZS5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAkc3RhdGUuZ28oJ2xhbmRpbmdQYWdlJyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICB2YXIgc2V0VXNlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKS50aGVuKGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgICAgICAgICAgIHNjb3BlLnVzZXIgPSB1c2VyO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgdmFyIHJlbW92ZVVzZXIgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgc2NvcGUudXNlciA9IG51bGw7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICBzZXRVc2VyKCk7XG5cbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLmxvZ2luU3VjY2Vzcywgc2V0VXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5sb2dvdXRTdWNjZXNzLCByZW1vdmVVc2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LCByZW1vdmVVc2VyKTtcblxuICAgICAgICB9XG5cbiAgICB9O1xuXG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ3JhbmRvR3JlZXRpbmcnLCBmdW5jdGlvbiAoUmFuZG9tR3JlZXRpbmdzKSB7XG5cbiAgICByZXR1cm4ge1xuICAgICAgICByZXN0cmljdDogJ0UnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL3JhbmRvLWdyZWV0aW5nL3JhbmRvLWdyZWV0aW5nLmh0bWwnLFxuICAgICAgICBsaW5rOiBmdW5jdGlvbiAoc2NvcGUpIHtcbiAgICAgICAgICAgIHNjb3BlLmdyZWV0aW5nID0gUmFuZG9tR3JlZXRpbmdzLmdldFJhbmRvbUdyZWV0aW5nKCk7XG4gICAgICAgIH1cbiAgICB9O1xuXG59KTsiXSwic291cmNlUm9vdCI6Ii9zb3VyY2UvIn0=
