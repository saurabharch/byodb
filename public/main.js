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
        templateUrl: 'js/home/home.html',
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcC5qcyIsImFib3V0L2Fib3V0LmpzIiwiZG9jcy9kb2NzLmpzIiwiZnNhL2ZzYS1wcmUtYnVpbHQuanMiLCJjcmVhdGVEQi9jcmVhdGVEQi5jb250cm9sbGVyLmpzIiwiY3JlYXRlREIvY3JlYXRlREIuZmFjdG9yeS5qcyIsImNyZWF0ZURCL2NyZWF0ZURCLnN0YXRlLmpzIiwiaG9tZS9ob21lLmNvbnRyb2xsZXIuanMiLCJob21lL2hvbWUuZmFjdG9yeS5qcyIsImhvbWUvaG9tZS5zdGF0ZS5qcyIsImxhbmRpbmdQYWdlL2xhbmRpbmdQYWdlLnN0YXRlLmpzIiwibG9naW4vbG9naW4uanMiLCJtZW1iZXJzLW9ubHkvbWVtYmVycy1vbmx5LmpzIiwib2F1dGgvb2F1dGgtYnV0dG9uLmRpcmVjdGl2ZS5qcyIsInNpZ251cC9zaWdudXAuanMiLCJ0YWJsZS9hc3NvY2lhdGlvbi5jb250cm9sbGVyLmpzIiwidGFibGUvZGVsZXRlREJNb2RhbC5qcyIsInRhYmxlL2RlbGV0ZVRhYmxlTW9kYWwuanMiLCJ0YWJsZS9qb2luLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS9xdWVyeS5jb250cm9sbGVyLmpzIiwidGFibGUvc2luZ2xldGFibGUuY29udHJvbGxlci5qcyIsInRhYmxlL3RhYmxlLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS90YWJsZS5mYWN0b3J5LmpzIiwidGFibGUvdGFibGUuc3RhdGUuanMiLCJ0YWJsZS90aHJvdWdoLmNvbnRyb2xsZXIuanMiLCJ0YWJsZS90aHJvdWdoTW9kYWwuY29udHJvbGxlci5qcyIsImNvbW1vbi9mYWN0b3JpZXMvRnVsbHN0YWNrUGljcy5qcyIsImNvbW1vbi9mYWN0b3JpZXMvUmFuZG9tR3JlZXRpbmdzLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvZnVsbHN0YWNrLWxvZ28vZnVsbHN0YWNrLWxvZ28uanMiLCJjb21tb24vZGlyZWN0aXZlcy9uYXZiYXIvbmF2YmFyLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvcmFuZG8tZ3JlZXRp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LGlCQUFBLFlBQUE7QUFKQSxTQUFBO0FBTUEsZUFBQTtBQUNBLDJCQUFBLHVCQUFBLFFBQUEsRUFBQTtBQUNBLDJCQUFBLFVBQUEsQ0FBQSxXQUFBLFNBQUEsTUFBQSxDQUFBLEVBQUEsUUFBQTtBQUNBLHVCQUFBLEdBQUEsTUFBQSxDQUFBLFFBQUEsQ0FBQTtBQUNBO0FBSkEsU0FBQTtBQU1BLEtBYkE7O0FBZUEsUUFBQSxNQUFBLENBQUEsVUFBQSxhQUFBLEVBQUE7QUFDQSxzQkFBQSxZQUFBLENBQUEsSUFBQSxDQUFBLENBQ0EsV0FEQSxFQUVBLFVBQUEsU0FBQSxFQUFBO0FBQ0EsbUJBQUEsVUFBQSxHQUFBLENBQUEsaUJBQUEsQ0FBQTtBQUNBLFNBSkEsQ0FBQTtBQU1BLEtBUEE7O0FBU0EsUUFBQSxPQUFBLENBQUEsYUFBQSxFQUFBLFVBQUEsS0FBQSxFQUFBLE9BQUEsRUFBQSxVQUFBLEVBQUEsV0FBQSxFQUFBLEVBQUEsRUFBQTs7QUFFQSxpQkFBQSxpQkFBQSxDQUFBLFFBQUEsRUFBQTtBQUNBLGdCQUFBLE9BQUEsU0FBQSxJQUFBO0FBQ0Esb0JBQUEsTUFBQSxDQUFBLEtBQUEsRUFBQSxFQUFBLEtBQUEsSUFBQTtBQUNBLHVCQUFBLFVBQUEsQ0FBQSxZQUFBLFlBQUE7QUFDQSxtQkFBQSxLQUFBLElBQUE7QUFDQTs7OztBQUlBLGFBQUEsZUFBQSxHQUFBLFlBQUE7QUFDQSxtQkFBQSxDQUFBLENBQUEsUUFBQSxJQUFBO0FBQ0EsU0FGQTs7QUFJQSxhQUFBLGVBQUEsR0FBQSxVQUFBLFVBQUEsRUFBQTs7Ozs7Ozs7OztBQVVBLGdCQUFBLEtBQUEsZUFBQSxNQUFBLGVBQUEsSUFBQSxFQUFBO0FBQ0EsdUJBQUEsR0FBQSxJQUFBLENBQUEsUUFBQSxJQUFBLENBQUE7QUFDQTs7Ozs7QUFLQSxtQkFBQSxNQUFBLEdBQUEsQ0FBQSxVQUFBLEVBQUEsSUFBQSxDQUFBLGlCQUFBLEVBQUEsS0FBQSxDQUFBLFlBQUE7QUFDQSx1QkFBQSxJQUFBO0FBQ0EsYUFGQSxDQUFBO0FBSUEsU0FyQkE7O0FB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LFdBQUEsR0FBQSxVQUFBLEtBQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxjQUFBLE1BQUEsR0FBQSxVQUFBLE1BQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxDQUFBLGVBQUEsRUFBQSxLQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSkE7O0FBTUEsV0FBQSxlQUFBO0FBQ0EsQ0FwQkE7O0FDQUEsSUFBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxtQkFBQSxLQUFBLENBQUEsVUFBQSxFQUFBO0FBQ0EsYUFBQSxXQURBO0FBRUEscUJBQUEsMkJBRkE7QUFHQSxvQkFBQSxjQUhBO0FBSUEsaUJBQUE7QUFDQSwwQkFBQSxzQkFBQSxXQUFBLEVBQUE7QUFDQSx1QkFBQSxZQUFBLGVBQUEsRUFBQTtBQUNBO0FBSEE7QUFKQSxLQUFBO0FBV0EsQ0FaQTtBQ0FBLElBQUEsVUFBQSxDQUFBLFVBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBOztBQUVBLFdBQUEsTUFBQSxHQUFBLE1BQUE7QUFDQSxDQUhBOztBQ0FBLElBQUEsT0FBQSxDQUFBLGFBQUEsRUFBQSxVQUFBLEtBQUEsRUFBQTs7QUFFQSxRQUFBLGNBQUEsRUFBQTs7QUFFQSxhQUFBLFNBQUEsQ0FBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLElBQUEsSUFBQTtBQUNBOztBQUVBLGdCQUFBLFNBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxlQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsZ0JBQUEsUUFBQSxHQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLE1BQUEsQ0FBQSxtQkFBQSxJQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsV0FBQSxXQUFBO0FBQ0EsQ0FuQkE7QUNBQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLG1CQUFBLEtBQUEsQ0FBQSxNQUFBLEVBQUE7QUFDQSxh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QSxTQUZBLEVBRUEsS0FGQSxDQUVBLFlBQUE7QUFDQSxtQkFBQSxLQUFBLEdBQUEsOENBQUE7QUFDQSxTQUpBO0FBTUEsS0FSQTtBQVVBLENBZkE7O0FDVkEsSUFBQSxVQUFBLENBQUEseUJBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxpQkFBQSxFQUFBLFdBQUEsRUFBQSxZQUFBLEVBQUEsV0FBQSxFQUFBLFlBQUEsRUFBQSxNQUFBLEVBQUEsUUFBQSxFQUFBLFlBQUEsRUFBQSxTQUFBLEVBQUEsT0FBQSxFQUFBLEdBQUEsRUFBQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxhQUFBLE1BQUE7O0FBRUEsV0FBQSxXQUFBLEdBQUEsUUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxZQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLFNBQUE7O0FBRUEsV0FBQSxPQUFBLEdBQUEsT0FBQTs7QUFFQSxXQUFBLEdBQUEsR0FBQSxHQUFBOztBQUVBLFdBQUEsV0FBQSxHQUFBLFlBQUE7O0FBRUEsZUFBQSxPQUFBLEdBQUEsS0FBQSxHQUFBO0FBQ0EsZ0JBQUEsR0FBQSxDQUFBLE9BQUEsT0FBQTtBQUNBLEtBSkE7O0FBUUEsYUFBQSxhQUFBLEdBQUE7QUFDQSxlQUFBLE9BQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxRQUFBLFNBQUEsQ0FBQSxDQUFBOztBQUdBLGFBQUEsSUFBQSxJQUFBLElBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxPQUFBLENBQUEsSUFBQSxDQUFBLElBQUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7OztBQUlBLGFBQUEsVUFBQSxHQUFBO0FBQ0EsZUFBQSxhQUFBLEdBQUEsRUFBQTtBQUNBLGlCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLFlBQUEsRUFBQTtBQUNBLGlCQUFBLElBQUEsSUFBQSxJQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBLFVBQUEsSUFBQSxDQUFBLElBQUEsSUFBQSxDQUFBO0FBQ0E7QUFDQSxtQkFBQSxhQUFBLENBQUEsSUFBQSxDQUFBLFNBQUE7QUFDQSxTQU5BO0FBT0E7OztBQUdBOztBQUdBLFdBQUEsYUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLE9BQUEsRUFBQSxPQUFBLEVBQUEsR0FBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLDBCQUFBLEtBQUE7QUFDQSxxQkFBQSxhQUFBLENBQUEsTUFBQSxFQUFBLE9BQUEsRUFBQSxPQUFBLEVBQUEsR0FBQSxFQUFBLEdBQUEsRUFDQSxJQURBLENBQ0EsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxjQUFBLEVBQUEsRUFBQSxRQUFBLE9BQUEsTUFBQSxFQUFBLFdBQUEsT0FBQSxTQUFBLEVBQUEsRUFBQSxFQUFBLFFBQUEsSUFBQSxFQUFBO0FBQ0EsU0FIQTtBQUlBLEtBTkE7O0FBVUEsV0FBQSxFQUFBLEdBQUEsWUFBQTtBQUNBLDBCQUFBLEtBQUEsQ0FBQSxPQUFBLFFBQUEsQ0FBQSxJQUFBO0FBQ0EsS0FGQTs7QUFJQSxXQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsMEJBQUEsT0FBQSxDQUFBLFFBQUE7QUFDQSxLQUZBO0FBR0EsQ0F0RUE7QUNBQSxJQUFBLFVBQUEsQ0FBQSxjQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLElBQUEsRUFBQTs7QUFFQSxXQUFBLEtBQUEsR0FBQSxDQUFBLE9BQUEsRUFBQSxPQUFBLEVBQUEsT0FBQSxDQUFBOztBQUVBLFdBQUEsaUJBQUEsR0FBQSxJQUFBOztBQUVBLFdBQUEsSUFBQSxHQUFBLFVBQUEsSUFBQSxFQUFBOztBQUVBLFlBQUEsZ0JBQUEsVUFBQSxJQUFBLENBQUE7QUFDQSx1QkFBQSxPQUFBLGlCQURBO0FBRUEseUJBQUEsc0JBRkE7QUFHQSx3QkFBQSxzQkFIQTtBQUlBLGtCQUFBLElBSkE7QUFLQSxxQkFBQTtBQUNBLHVCQUFBLGlCQUFBO0FBQ0EsMkJBQUEsT0FBQSxLQUFBO0FBQ0E7QUFIQTtBQUxBLFNBQUEsQ0FBQTs7QUFZQSxzQkFBQSxNQUFBLENBQUEsSUFBQSxDQUFBLFVBQUEsWUFBQSxFQUFBO0FBQ0EsbUJBQUEsUUFBQSxHQUFBLFlBQUE7QUFDQSxTQUZBLEVBRUEsWUFBQTtBQUNBLGlCQUFBLElBQUEsQ0FBQSx5QkFBQSxJQUFBLElBQUEsRUFBQTtBQUNBLFNBSkE7QUFLQSxLQW5CQTs7QUFxQkEsV0FBQSxlQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsaUJBQUEsR0FBQSxDQUFBLE9BQUEsaUJBQUE7QUFDQSxLQUZBO0FBSUEsQ0EvQkE7O0FBaUNBLElBQUEsVUFBQSxDQUFBLHNCQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsaUJBQUEsRUFBQSxLQUFBLEVBQUEsWUFBQSxFQUFBLFdBQUEsRUFBQSxZQUFBLEVBQUEsTUFBQSxFQUFBOztBQUdBLFdBQUEsVUFBQSxHQUFBLGVBQUE7QUFDQSxXQUFBLE1BQUEsR0FBQSxhQUFBLE1BQUE7O0FBRUEsV0FBQSxXQUFBLEdBQUEsWUFBQTtBQUNBLDBCQUFBLEtBQUEsQ0FBQSxPQUFBLFFBQUEsQ0FBQSxJQUFBO0FBQ0EscUJBQUEsUUFBQSxDQUFBLE9BQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxZQUFBO0FBQ0Esd0JBQUEsUUFBQSxDQUFBLE9BQUEsTUFBQTtBQUNBLFNBSEEsRUFJQSxJQUpBLENBSUEsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxNQUFBLEVBQUEsRUFBQSxFQUFBLEVBQUEsUUFBQSxJQUFBLEVBQUE7QUFDQSxTQU5BO0FBT0EsS0FUQTs7QUFXQSxXQUFBLEtBQUEsR0FBQSxLQUFBO0FBQ0EsV0FBQSxRQUFBLEdBQUE7QUFDQSxjQUFBLE9BQUEsS0FBQSxDQUFBLENBQUE7QUFEQSxLQUFBOztBQUlBLFdBQUEsRUFBQSxHQUFBLFlBQUE7QUFDQSwwQkFBQSxLQUFBLENBQUEsT0FBQSxRQUFBLENBQUEsSUFBQTtBQUNBLEtBRkE7O0FBSUEsV0FBQSxNQUFBLEdBQUEsWUFBQTtBQUNBLDBCQUFBLE9BQUEsQ0FBQSxRQUFBO0FBQ0EsS0FGQTtBQUdBLENBN0JBO0FDakNBLElBQUEsVUFBQSxDQUFBLGNBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQTs7QUFFQSxXQUFBLGlCQUFBLEdBQUEsSUFBQTs7QUFFQSxXQUFBLElBQUEsR0FBQSxVQUFBLElBQUEsRUFBQTs7QUFFQSxZQUFBLGdCQUFBLFVBQUEsSUFBQSxDQUFBO0FBQ0EsdUJBQUEsT0FBQSxpQkFEQTtBQUVBLHlCQUFBLHNCQUZBO0FBR0Esd0JBQUEsc0JBSEE7QUFJQSxrQkFBQSxJQUpBO0FBS0EscUJBQUE7QUFDQSx1QkFBQSxpQkFBQTtBQUNBLDJCQUFBLE9BQUEsS0FBQTtBQUNBO0FBSEE7QUFMQSxTQUFBLENBQUE7O0FBWUEsc0JBQUEsTUFBQSxDQUFBLElBQUEsQ0FBQSxVQUFBLFlBQUEsRUFBQTtBQUNBLG1CQUFBLFFBQUEsR0FBQSxZQUFBO0FBQ0EsU0FGQSxFQUVBLFlBQUE7QUFDQSxpQkFBQSxJQUFBLENBQUEseUJBQUEsSUFBQSxJQUFBLEVBQUE7QUFDQSxTQUpBO0FBS0EsS0FuQkE7QUFxQkEsQ0F6QkE7O0FBNEJBLElBQUEsVUFBQSxDQUFBLHNCQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsaUJBQUEsRUFBQSxLQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxhQUFBLE1BQUE7O0FBRUEsV0FBQSxZQUFBLEdBQUEsZUFBQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EscUJBQUEsUUFBQSxDQUFBLE9BQUEsTUFBQTtBQUNBLGVBQUEsRUFBQSxDQUFBLE1BQUEsRUFBQSxFQUFBLEVBQUEsRUFBQSxRQUFBLElBQUEsRUFBQTtBQUNBLEtBSEE7O0FBS0EsV0FBQSxNQUFBLEdBQUEsWUFBQTtBQUNBLDBCQUFBLE9BQUEsQ0FBQSxRQUFBO0FBQ0EsS0FGQTtBQUdBLENBZEE7QUM1QkEsSUFBQSxVQUFBLENBQUEsZUFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUEsU0FBQSxFQUFBOztBQUVBLFdBQUEsU0FBQSxHQUFBLFNBQUE7O0FBR0EsYUFBQSxhQUFBLEdBQUE7QUFDQSxlQUFBLE9BQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxRQUFBLE9BQUEsU0FBQSxDQUFBLENBQUEsQ0FBQTs7QUFHQSxhQUFBLElBQUEsSUFBQSxJQUFBLEtBQUEsRUFBQTtBQUNBLGdCQUFBLFNBQUEsWUFBQSxJQUFBLFNBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxJQUFBO0FBQ0E7QUFDQTtBQUNBOztBQUVBOzs7QUFJQSxhQUFBLFVBQUEsR0FBQTtBQUNBLFlBQUEsS0FBQTtBQUNBLGVBQUEsYUFBQSxHQUFBLEVBQUE7QUFDQSxrQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxZQUFBLEVBQUE7QUFDQSxpQkFBQSxJQUFBLElBQUEsSUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxTQUFBLFlBQUEsSUFBQSxTQUFBLFlBQUEsRUFBQSxVQUFBLElBQUEsQ0FBQSxJQUFBLElBQUEsQ0FBQTtBQUNBO0FBQ0EsbUJBQUEsYUFBQSxDQUFBLElBQUEsQ0FBQSxTQUFBO0FBQ0EsU0FOQTtBQU9BOzs7QUFHQTtBQUdBLENBckNBO0FDQUEsSUFBQSxVQUFBLENBQUEsZ0JBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBOztBQUVBLFdBQUEsT0FBQSxHQUFBLFVBQUEsZUFBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsQ0FBQSxlQUFBLEVBQUEsT0FBQSxJQUFBLENBQUEsS0FDQTtBQUNBLGlCQUFBLElBQUEsSUFBQSxJQUFBLEdBQUEsRUFBQTtBQUNBLG9CQUFBLFVBQUEsSUFBQSxJQUFBLEVBQUEsUUFBQSxHQUFBLFdBQUEsRUFBQTtBQUNBLG9CQUFBLFlBQUEsZ0JBQUEsUUFBQSxHQUFBLFdBQUEsRUFBQTtBQUNBLHdCQUFBLEdBQUEsQ0FBQSxPQUFBLEVBQUEsU0FBQSxFQUFBLFFBQUEsT0FBQSxDQUFBLFNBQUEsTUFBQSxDQUFBLENBQUE7QUFDQSxvQkFBQSxRQUFBLE9BQUEsQ0FBQSxTQUFBLE1BQUEsQ0FBQSxDQUFBLEVBQUEsT0FBQSxJQUFBO0FBQ0E7QUFDQTtBQUNBLGVBQUEsS0FBQTtBQUNBLEtBWEE7QUFhQSxDQWZBO0FDQUEsSUFBQSxVQUFBLENBQUEsaUJBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBLFdBQUEsRUFBQSxPQUFBLEVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxZQUFBLEVBQUEsSUFBQSxFQUFBOzs7O0FBSUEsV0FBQSxTQUFBLEdBQUEsYUFBQSxNQUFBO0FBQ0EsV0FBQSxZQUFBLEdBQUEsYUFBQSxTQUFBO0FBQ0EsV0FBQSxXQUFBLEdBQUEsWUFBQSxDQUFBLEVBQUEsSUFBQSxDQUFBLFVBQUEsQ0FBQSxFQUFBLENBQUEsRUFBQTtBQUNBLFlBQUEsRUFBQSxFQUFBLEdBQUEsRUFBQSxFQUFBLEVBQUEsT0FBQSxDQUFBO0FBQ0EsWUFBQSxFQUFBLEVBQUEsR0FBQSxFQUFBLEVBQUEsRUFBQSxPQUFBLENBQUEsQ0FBQTtBQUNBLGVBQUEsQ0FBQTtBQUNBLEtBSkEsQ0FBQTtBQUtBLFdBQUEsV0FBQSxHQUFBLEtBQUE7QUFDQSxXQUFBLFlBQUEsR0FBQSxZQUFBOztBQUdBLFFBQUEsT0FBQSxZQUFBLENBQUEsTUFBQSxHQUFBLENBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxZQUFBLENBQUEsQ0FBQSxFQUFBLFNBQUEsTUFBQSxhQUFBLFNBQUEsRUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxlQUFBLEVBQUEsRUFBQSxRQUFBLGFBQUEsTUFBQSxFQUFBLFdBQUEsYUFBQSxTQUFBLEVBQUE7QUFDQTtBQUNBOztBQUdBLGFBQUEsZ0JBQUEsR0FBQTtBQUNBLFlBQUEsY0FBQSxFQUFBO0FBQ0EsZUFBQSxZQUFBLENBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxNQUFBLEtBQUEsT0FBQSxZQUFBLElBQUEsSUFBQSxhQUFBLEtBQUEsUUFBQSxFQUFBO0FBQ0EsNEJBQUEsSUFBQSxNQUFBLElBQUEsSUFBQSxNQUFBO0FBQ0EsYUFGQSxNQUVBLElBQUEsSUFBQSxNQUFBLEtBQUEsT0FBQSxZQUFBLElBQUEsSUFBQSxhQUFBLEtBQUEsUUFBQSxFQUFBO0FBQ0EsNEJBQUEsSUFBQSxNQUFBLElBQUEsSUFBQSxNQUFBO0FBQ0E7QUFDQSxTQU5BO0FBT0EsZUFBQSxXQUFBLEdBQUEsV0FBQTtBQUNBOztBQUVBOztBQUdBLFdBQUEsWUFBQSxHQUFBLFlBQUE7O0FBRUEsV0FBQSxPQUFBLEdBQUEsQ0FBQTs7QUFFQSxXQUFBLEdBQUEsR0FBQSxPQUFBLFdBQUEsQ0FBQSxHQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLElBQUEsRUFBQTtBQUNBLEtBRkEsQ0FBQTs7O0FBS0EsV0FBQSxVQUFBLEdBQUEsS0FBQTtBQUNBLFdBQUEsWUFBQSxHQUFBLFlBQUE7QUFDQSxlQUFBLFVBQUEsR0FBQSxDQUFBLE9BQUEsVUFBQTtBQUNBLEtBRkE7O0FBSUEsV0FBQSxjQUFBLEdBQUEsVUFBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLGFBQUEsRUFBQTtBQUNBLGFBQUEsSUFBQSxJQUFBLGNBQUEsTUFBQSxHQUFBLENBQUEsRUFBQSxLQUFBLENBQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxNQUFBLGNBQUEsQ0FBQSxDQUFBO0FBQ0EsZ0JBQUEsU0FBQSxDQUFBO0FBQ0Esb0JBQUEsR0FBQSxDQUFBLEdBQUE7QUFDQSxnQkFBQSxJQUFBLFFBQUEsRUFBQTtBQUNBLDZCQUFBLFNBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLElBQUEsUUFBQSxFQUFBLENBQUEsRUFBQSxPQUFBLENBQUEsRUFBQSxNQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsMkJBQUEsV0FBQSxHQUFBLE1BQUE7QUFDQTtBQUNBLGlCQUpBO0FBS0E7QUFDQTtBQUNBLGVBQUEsVUFBQSxHQUFBLEtBQUE7QUFDQSxLQWRBOztBQWdCQSxXQUFBLFNBQUEsR0FBQSxVQUFBLGFBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxXQUFBLEVBQUE7QUFDQSwwQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxRQUFBLEdBQUEsSUFBQTtBQUNBLGFBRkE7QUFHQSxTQUpBLE1BSUE7QUFDQSwwQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxvQkFBQSxRQUFBLEdBQUEsS0FBQTtBQUNBLGFBRkE7QUFHQTtBQUNBLEtBVkE7O0FBWUEsV0FBQSxnQkFBQSxHQUFBLFVBQUEsYUFBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLFdBQUEsS0FBQSxJQUFBLEVBQUE7QUFDQSxtQkFBQSxXQUFBLEdBQUEsS0FBQTtBQUNBO0FBQ0EsS0FKQTs7QUFNQSxXQUFBLFNBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsR0FBQSxFQUFBLGFBQUEsRUFBQTtBQUNBLFlBQUEsU0FBQSxjQUFBLE1BQUEsR0FBQSxDQUFBO0FBQ0EscUJBQUEsU0FBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsR0FBQSxFQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSxtQkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsU0FKQTtBQUtBLEtBUEE7O0FBU0EsV0FBQSxZQUFBLEdBQUEsVUFBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLFVBQUEsRUFBQTtBQUNBLHFCQUFBLFlBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLFVBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSxtQkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0E7QUFDQSxTQUxBO0FBTUEsS0FQQTs7QUFTQSxXQUFBLE1BQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxTQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsQ0FBQSxVQUFBLE9BQUEsRUFBQTtBQUNBLG1CQUFBLElBQUEsQ0FBQSxRQUFBLE1BQUEsQ0FBQSxDQUFBLEVBQUEsS0FBQTtBQUNBLFNBRkE7QUFHQSxZQUFBLFNBQUEsT0FBQSxJQUFBLENBQUEsVUFBQSxDQUFBLEVBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBO0FBQ0EsU0FGQSxDQUFBO0FBR0EsWUFBQSxPQUFBLE1BQUEsR0FBQSxDQUFBLEVBQUE7QUFDQSx5QkFBQSxNQUFBLENBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxPQUFBLENBQUEsSUFBQSxDQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsdUJBQUEsV0FBQSxHQUFBLE1BQUE7QUFDQTtBQUNBLGFBSkE7QUFNQSxTQVBBLE1BT0E7QUFDQSx5QkFBQSxNQUFBLENBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxDQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsdUJBQUEsV0FBQSxHQUFBLE1BQUE7QUFDQTtBQUNBLGFBSkE7QUFLQTtBQUNBLEtBdEJBOztBQXdCQSxXQUFBLFNBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUE7QUFDQSxZQUFBLFVBQUEsT0FBQSxPQUFBLENBQUEsSUFBQSxDQUFBLEdBQUEsRUFBQSxLQUFBLENBQUEsTUFBQSxDQUFBO0FBQ0EsWUFBQSxPQUFBLEVBQUE7QUFDQSxnQkFBQSxhQUFBLFFBQUEsSUFBQSxDQUFBLFVBQUEsQ0FBQSxFQUFBLENBQUEsRUFBQTtBQUNBLHVCQUFBLElBQUEsQ0FBQTtBQUNBLGFBRkEsQ0FBQTtBQUdBLGdCQUFBLFdBQUEsT0FBQSxXQUFBLENBQUEsQ0FBQSxJQUFBLENBQUE7QUFDQSxnQkFBQSxhQUFBLFlBQUEsU0FBQSxRQUFBLEVBQUE7O0FBRUEseUJBQUEsU0FBQSxDQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUNBLElBREEsQ0FDQSxZQUFBO0FBQ0EsdUJBQUEsYUFBQSxjQUFBLENBQUEsYUFBQSxNQUFBLEVBQUEsYUFBQSxTQUFBLENBQUE7QUFDQSxhQUhBLEVBSUEsSUFKQSxDQUlBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsdUJBQUEsV0FBQSxHQUFBLFNBQUEsQ0FBQSxDQUFBO0FBQ0E7QUFDQTtBQUNBLGFBUkE7QUFTQSxTQWhCQSxNQWdCQTtBQUNBLGdCQUFBLGFBQUEsT0FBQSxPQUFBLENBQUEsTUFBQSxHQUFBLENBQUE7QUFDQSxnQkFBQSxhQUFBLFlBQUEsVUFBQTtBQUNBLHlCQUFBLFNBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLFVBQUEsRUFDQSxJQURBLENBQ0EsWUFBQTtBQUNBLHVCQUFBLGFBQUEsY0FBQSxDQUFBLGFBQUEsTUFBQSxFQUFBLGFBQUEsU0FBQSxDQUFBO0FBQ0EsYUFIQSxFQUlBLElBSkEsQ0FJQSxVQUFBLFFBQUEsRUFBQTtBQUNBLHVCQUFBLFdBQUEsR0FBQSxTQUFBLENBQUEsQ0FBQTtBQUNBO0FBQ0E7QUFDQSxhQVJBO0FBU0E7QUFFQSxLQWhDQTs7Ozs7O0FBc0NBLGFBQUEsYUFBQSxHQUFBO0FBQ0EsZUFBQSxPQUFBLEdBQUEsRUFBQTtBQUNBLGVBQUEsZUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLFFBQUEsT0FBQSxXQUFBLENBQUEsQ0FBQSxDQUFBOztBQUdBLGFBQUEsSUFBQSxJQUFBLElBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JBQUEsU0FBQSxZQUFBLElBQUEsU0FBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxPQUFBLENBQUEsSUFBQSxDQUFBLElBQUE7QUFDQSx1QkFBQSxlQUFBLENBQUEsSUFBQSxDQUFBLElBQUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7O0FBRUEsYUFBQSxvQkFBQSxHQUFBO0FBQ0EsWUFBQSxPQUFBLFlBQUEsQ0FBQSxNQUFBLEdBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsY0FBQSxHQUFBLEVBQUE7QUFDQSxtQkFBQSxZQUFBLENBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsSUFBQSxNQUFBLEtBQUEsT0FBQSxZQUFBLElBQUEsSUFBQSxhQUFBLEtBQUEsU0FBQSxFQUFBO0FBQ0Esd0JBQUEsVUFBQSxFQUFBO0FBQ0EsNEJBQUEsSUFBQSxHQUFBLElBQUEsTUFB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QUEsRUFBQTs7QUFFQSxXQUFBLFNBQUEsR0FBQSxVQUFBLEdBQUEsRUFBQSxPQUFBLEVBQUEsR0FBQSxFQUFBLENBQUEsRUFBQSxDQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsT0FBQSxlQUFBO0FBQ0EsWUFBQSxRQUFBLEtBQUE7QUFDQSxZQUFBLFVBQUEsS0FBQSxDQUFBLENBQUE7QUFDQSxhQUFBLElBQUEsSUFBQSxDQUFBLEVBQUEsSUFBQSxPQUFBLGVBQUEsQ0FBQSxNQUFBLEVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsTUFBQSxPQUFBLGVBQUEsQ0FBQSxDQUFBLENBQUE7QUFDQSxvQkFBQSxHQUFBLENBQUEsR0FBQTtBQUNBLGdCQUFBLElBQUEsSUFBQSxNQUFBLENBQUEsRUFBQTtBQUNBLHdCQUFBLElBQUE7QUFDQSxvQkFBQSxJQUFBLE9BQUEsQ0FBQSxFQUFBLElBQUEsT0FBQSxJQUFBLE9BQUE7QUFDQSxvQkFBQSxPQUFBLElBQUEsT0FBQTtBQUNBO0FBQ0E7QUFDQSxZQUFBLENBQUEsS0FBQSxFQUFBO0FBQ0EsZ0JBQUEsU0FBQSxFQUFBO0FBQ0EsbUJBQUEsSUFBQSxJQUFBLENBQUE7QUFDQSxtQkFBQSxPQUFBLElBQUEsT0FBQTtBQUNBLG1CQUFBLGVBQUEsQ0FBQSxJQUFBLENBQUEsTUFBQTtBQUNBO0FBQ0EsS0FuQkE7O0FBcUJBLFdBQUEsYUFBQSxHQUFBLFlBQUE7QUFDQSxZQUFBLE9BQUEsRUFBQSxNQUFBLE9BQUEsZUFBQSxFQUFBLFNBQUEsT0FBQSxlQUFBLEVBQUE7QUFDQSxxQkFBQSxhQUFBLENBQUEsT0FBQSxTQUFBLEVBQUEsT0FBQSxZQUFBLEVBQUEsSUFBQTtBQUNBLEtBSEE7O0FBTUEsV0FBQSxXQUFBLEdBQUEsWUFBQTtBQUNBLHFCQUFBLFdBQUEsQ0FBQSxPQUFBLFlBQUEsRUFDQSxJQURBLENBQ0EsWUFBQTtBQUNBLG1CQUFBLEVBQUEsQ0FBQSxPQUFBLEVBQUEsRUFBQSxRQUFBLE9BQUEsU0FBQSxFQUFBLEVBQUEsRUFBQSxRQUFBLElBQUEsRUFBQTtBQUNBLFNBSEE7QUFJQSxLQUxBOzs7O0FBU0EsV0FBQSx3QkFBQSxHQUFBLEVBQUE7O0FBRUEsV0FBQSxhQUFBLEdBQUEsRUFBQTs7QUFFQSxpQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLElBQUEsTUFBQSxLQUFBLE9BQUEsWUFBQSxJQUFBLE9BQUEsd0JBQUEsQ0FBQSxPQUFBLENBQUEsSUFBQSxNQUFBLEtBQUEsQ0FBQSxDQUFBLEVBQUE7QUFDQSxtQkFBQSx3QkFBQSxDQUFBLElBQUEsQ0FBQSxJQUFBLE1BQUE7QUFDQSxTQUZBLE1BRUEsSUFBQSxJQUFBLE1BQUEsS0FBQSxPQUFBLFlBQUEsSUFBQSxPQUFBLHdCQUFBLENBQUEsT0FBQSxDQUFBLElBQUEsTUFBQSxLQUFBLENBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsd0JBQUEsQ0FBQSxJQUFBLENBQUEsSUFBQSxNQUFBO0FBQ0E7QUFDQSxLQU5BOztBQVFBLFdBQUEsYUFBQSxHQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLGFBQUEsQ0FBQSxPQUFBLENBQUEsT0FBQSx3QkFBQSxDQUFBLEdBQUEsQ0FBQSxNQUFBLENBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsYUFBQSxDQUFBLElBQUEsQ0FBQSxPQUFBLHdCQUFBLENBQUEsR0FBQSxDQUFBO0FBQ0EsU0FGQSxNQUVBO0FBQ0EsZ0JBQUEsSUFBQSxPQUFBLGFBQUEsQ0FBQSxPQUFBLENBQUEsT0FBQSx3QkFBQSxDQUFBLEdBQUEsQ0FBQSxDQUFBO0FBQ0EsbUJBQUEsYUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBLEVBQUEsQ0FBQTtBQUNBO0FBQ0EsS0FQQTs7QUFTQSxXQUFBLGVBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsa0JBQUEsR0FBQSxZQUFBO0FBQ0EsWUFBQSxxQkFBQSxFQUFBO0FBQ0EsZUFBQSxhQUFBLENBQUEsT0FBQSxDQUFBLFVBQUEsU0FBQSxFQUFBO0FBQ0EsbUJBQUEsbUJBQUEsSUFBQSxDQUFBLGFBQUEsa0JBQUEsQ0FBQSxPQUFBLFNB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QUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxNQUFBLEVBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQSxTQUFBLEVBQUEsV0FBQSxFQUFBLFlBQUEsRUFBQSxVQUFBLEVBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsU0FBQTs7QUFFQSxXQUFBLFdBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsTUFBQSxHQUFBLGFBQUEsTUFBQTs7QUFFQSxXQUFBLFlBQUEsR0FBQSxZQUFBOztBQUVBLFdBQUEsVUFBQSxHQUFBLFVBQUE7O0FBRUEsV0FBQSxnQkFBQSxHQUFBLGFBQUEsTUFBQSxHQUFBLFFBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsT0FBQSxTQUFBLENBQUEsSUFBQSxDQUFBLE1BQUE7O0FBRUEsV0FBQSxHQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsV0FBQSxDQUFBLElBQUEsQ0FBQSxHQUFBO0FBQ0EsS0FGQTs7QUFJQSxXQUFBLE1BQUEsR0FBQSxNQUFBLEM7O0FBRUEsV0FBQSxnQkFBQSxHQUFBLENBQUEsUUFBQSxFQUFBLFNBQUEsQ0FBQTs7QUFFQSxXQUFBLE1BQUEsR0FBQSxhQUFBLE1BQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsS0FBQTs7QUFFQSxXQUFBLGdCQUFBLEdBQUEsVUFBQSxXQUFBLEVBQUEsTUFBQSxFQUFBO0FBQ0EsZUFBQSxTQUFBLEdBQUEsSUFBQTtBQUNBLHFCQUFBLGdCQUFBLENBQUEsV0FBQSxFQUFBLE1BQUE7QUFDQSxLQUhBOztBQUtBLFdBQUEsWUFBQSxHQUFBLFVBQUEsU0FBQSxFQUFBO0FBQ0EsWUFBQSxjQUFBLGVBQUEsSUFBQSxjQUFBLG1CQUFBLEVBQUEsT0FBQSxJQUFBO0FBQ0EsS0FGQTs7QUFJQSxXQUFBLFdBQUEsR0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLHFCQUFBLFdBQUEsQ0FBQSxLQUFBLEVBQ0EsSUFEQSxDQUNBLFlBQUE7QUFDQSxtQkFBQSxFQUFBLENBQUEsT0FBQSxFQUFBLEVBQUEsUUFBQSxPQUFBLE1BQUEsRUFBQSxFQUFBLEVBQUEsUUFBQSxJQUFBLEVBQUE7QUFDQSxTQUhBO0FBSUEsS0FMQTs7QUFPQSxXQUFBLGNBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxVQUFBLENBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxVQUFBLEtBQUEsT0FBQSxLQUFBLENBQUEsTUFBQSxJQUFBLElBQUEsV0FBQSxLQUFBLE9BQUEsS0FBQSxDQUFBLE1BQUEsRUFBQSxPQUFBLElBQUEsR0FBQSxJQUFBLFNBQUE7QUFDQSxTQUZBO0FBR0EsS0FKQTs7QUFNQSxXQUFBLGFBQUEsR0FBQSxFQUFBOztBQUVBLFdBQUEsV0FBQSxHQUFBLGFBQUEsV0FBQTs7QUFFQSxXQUFBLFVBQUEsR0FBQSxVQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsY0FBQSxhQUFBLE1BQUEsR0FBQSxRQUFBO0FBQ0EsS0FGQTtBQUlBLENBMURBOztBQ0FBLElBQUEsT0FBQSxDQUFBLGNBQUEsRUFBQSxVQUFBLEtBQUEsRUFBQSxZQUFBLEVBQUE7O0FBRUEsUUFBQSxlQUFBLEVBQUE7O0FBRUEsYUFBQSxTQUFBLENBQUEsR0FBQSxFQUFBO0FBQ0EsZUFBQSxJQUFBLElBQUE7QUFDQTs7QUFFQSxpQkFBQSxZQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1CQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxjQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLEdBQUEsQ0FBQSxtQkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxTQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1CQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxNQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLElBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEdBQUEsU0FBQSxFQUFBLElBQUEsQ0FBQTtBQUNBLEtBRkE7O0FBSUEsaUJBQUEsYUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxJQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLGtCQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxFQUFBLElBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxNQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxJQUFBLENBQUEseUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQUEsRUFBQSxXQUFBLFNBQUEsRUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFNBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsS0FBQSxFQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEdBQUEsR0FBQSxHQUFBLEtBQUEsR0FBQSxHQUFBLEdBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFlBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsVUFBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLE1BQUEsQ0FBQSxtQkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsR0FBQSxVQUFBLEdBQUEsVUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFNBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0EsZUFBQSxNQUFBLElBQUEsQ0FBQSw0QkFBQSxNQUFBLEdBQUEsR0FBQSxHQUFBLFNBQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxDQUFBO0FBQ0EsS0FGQTtBQUdBLGlCQUFBLFdBQUEsR0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLGNBQUEsTUFBQSxHQUFBLGFBQUEsTUFBQTtBQUNBLGVBQUEsTUFBQSxJQUFBLENBQUEsZUFBQSxFQUFBLEtBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FKQTs7QUFNQSxpQkFBQSxXQUFBLEdBQUEsVUFBQSxZQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsTUFBQSxDQUFBLG1CQUFBLGFBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxhQUFBLFNBQUEsQ0FBQTtBQUNBLEtBRkE7O0FBSUEsaUJBQUEsZ0JBQUEsR0FBQSxVQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxjQUFBLEVBQUEsV0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxNQUFBLENBQUEsbUJBQUEsTUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGVBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG9DQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGtCQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1DQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxhQUFBLEdBQUEsVUFBQSxNQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLGlDQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxpQkFBQSxrQkFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUNBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBSEE7O0FBS0EsaUJBQUEsT0FBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLE1BQUEsRUFBQSxhQUFBLEVBQUEsZUFBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsRUFBQTtBQUNBLGFBQUEsTUFBQSxHQUFBLE1BQUE7QUFDQSxhQUFBLE1BQUEsR0FBQSxjQUFBLENBQUEsQ0FBQTtBQUNBLGFBQUEsYUFBQSxHQUFBLGFBQUE7QUFDQSxhQUFBLGVBQUEsR0FBQSxlQUFBO0FBQ0EsYUFBQSxZQUFBLEdBQUEsWUFBQTs7OztBQUlBLHFCQUFBLE9BQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQTtBQUNBLGdCQUFBLElBQUEsTUFBQSxLQUFBLE1BQUEsSUFBQSxJQUFBLE1BQUEsS0FBQSxLQUFBLE1BQUEsRUFBQTtBQUNBLHFCQUFBLEtBQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSxvQkFBQSxJQUFBLGFBQUEsS0FBQSxRQUFBLEVBQUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EseUJBQUEsTUFBQSxHQUFBLElBQUEsTUFBQTtBQUNBLGlCQUhBLE1BSUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EseUJBQUEsTUFBQSxHQUFBLElBQUEsTUFBQTtBQUNBO0FBQ0EsYUFWQSxNQVdBLElBQUEsSUFBQSxNQUFBLEtBQUEsS0FBQSxNQUFBLElBQUEsSUFBQSxNQUFBLEtBQUEsTUFBQSxFQUFBO0FBQ0EscUJBQUEsS0FBQSxHQUFBLElBQUEsTUFBQTtBQUNBLG9CQUFBLElBQUEsYUFBQSxLQUFBLFNBQUEsRUFBQTtBQUNBLHlCQUFBLE1BQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0EsaUJBSEEsTUFJQTtBQUNBLHlCQUFBLE1BQUEsR0FBQSxJQUFBLE1BQUE7QUFDQSx5QkFBQSxNQUFBLEdBQUEsSUFBQSxNQUFBO0FBQ0E7QUFDQTtBQUNBLFNBdkJBOztBQXlCQSxnQkFBQSxHQUFBLENBQUEsTUFBQSxFQUFBLElBQUE7O0FBRUEsZUFBQSxNQUFBLEdBQUEsQ0FBQSx1QkFBQSxFQUFBLElBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0F2Q0E7O0FBeUNBLGlCQUFBLGNBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxHQUFBLENBQUEsbUJBQUEsTUFBQSxHQUFBLEdBQUEsR0FBQSxTQUFBLEdBQUEsR0FBQSxHQUFBLEVBQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLFdBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxPQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLDJCQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsT0FBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQUhBOztBQUtBLGlCQUFBLGFBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxPQUFBLEVBQUEsT0FBQSxFQUFBLEdBQUEsRUFBQSxHQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsRUFBQTtBQUNBLGFBQUEsTUFBQSxHQUFBLE1BQUE7QUFDQSxhQUFBLE9BQUEsR0FBQSxPQUFBO0FBQ0EsYUFBQSxPQUFBLEdBQUEsT0FBQTtBQUNBLGFBQUEsR0FBQSxHQUFBLEdBQUE7QUFDQSxhQUFBLEdBQUEsR0FBQSxHQUFBOztBQUVBLGVBQUEsTUFBQSxHQUFBLENBQUEsNkJBQUEsRUFBQSxJQUFBLEVBQ0EsSUFEQSxDQUNBLFNBREEsQ0FBQTtBQUVBLEtBVkE7O0FBWUEsaUJBQUEsZUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxFQUFBLEVBQUEsTUFBQSxFQUFBLGFBQUEsRUFBQSxVQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsRUFBQTtBQUNBLGFBQUEsTUFBQSxHQUFBLE1BQUE7QUFDQSxhQUFBLE9BQUEsR0FBQSxTQUFBO0FBQ0EsYUFBQSxLQUFBLEdBQUEsRUFBQTtBQUNBLGFBQUEsTUFBQSxHQUFBLE1BQUE7QUFDQSxhQUFBLGFBQUEsR0FBQSxhQUFBO0FBQ0EsYUFBQSxVQUFBLEdBQUEsVUFBQTs7QUFFQSxlQUFBLE1BQUEsR0FBQSxDQUFBLCtCQUFBLEVBQUEsSUFBQSxFQUNBLElBREEsQ0FDQSxTQURBLENBQUE7QUFFQSxLQVhBOztBQWFBLGlCQUFBLFNBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsR0FBQSxDQUFBLG1CQUFBLE1BQUEsR0FBQSxHQUFBLEdBQUEsU0FBQSxHQUFBLGVBQUEsRUFDQSxJQURBLENBQ0EsU0FEQSxDQUFBO0FBRUEsS0FIQTs7QUFLQSxXQUFBLFlBQUE7QUFDQSxDQTVLQTtBQ0FBLElBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0EsbUJBQUEsS0FBQSxDQUFBLE9BQUEsRUFBQTtBQUNBLGFBQUEsVUFEQTtBQUVBLHFCQUFBLHFCQUZBO0FBR0Esb0JBQUEsV0FIQTtBQUlBLGlCQUFBO0FBQ0EsdUJBQUEsbUJBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLGFBQUEsWUFBQSxDQUFBLGFBQUEsTUFBQSxDQUFBO0FBQ0EsYUFIQTtBQUlBLDBCQUFBLHNCQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxhQUFBLGtCQUFBLENBQUEsYUFBQSxNQUFBLENBQUE7QUFDQSxhQU5BO0FBT0Esd0JBQUEsb0JBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLGFBQUEsYUFBQSxDQUFBLGFBQUEsTUFBQSxDQUFBO0FBQ0E7QUFUQTtBQUpBLEtBQUE7O0FBaUJBLG1CQUFBLEtBQUEsQ0FBQSxjQUFBLEVBQUE7QUFDQSxhQUFBLGFBREE7QUFFQSxxQkFBQSwyQkFGQTtBQUdBLG9CQUFBLGlCQUhBO0FBSUEsaUJBQUE7QUFDQSx5QkFBQSxxQkFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsYUFBQSxjQUFBLENBQUEsYUFBQSxNQUFBLEVBQUEsYUFBQSxTQUFBLENBQUE7QUFDQSxhQUhBO0FBSUEsMEJBQUEsc0JBQUEsWUFBQSxFQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLGFBQUEsZUFBQSxDQUFBLGFBQUEsTUFBQSxFQUFBLGFBQUEsU0FBQSxDQUFBO0FBQ0E7QUFOQTtBQUpBLEtBQUE7O0FBY0EsbUJBQUEsS0FBQSxDQUFBLFlBQUEsRUFBQTtBQUNBLGFBQUEsOEJBREE7QUFFQSxxQkFBQSxvQkFGQTtBQUdBLG9CQUFBLGVBSEE7QUFJQSxpQkFBQTtBQUNBLHVCQUFBLG1CQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxhQUFBLGNBQUEsQ0FBQSxhQUFBLEtBQUEsRUFBQSxhQUFBLE1BQUEsRUFBQSxhQUFBLFNBQUEsRUFBQSxhQUFBLEdBQUEsQ0FBQTtBQUNBO0FBSEE7QUFKQSxLQUFBOztBQVdBLG1CQUFBLEtBQUEsQ0FBQSxlQUFBLEVBQUE7QUFDQSxhQUFBLHFCQURBO0FBRUEscUJBQUEsdUJBRkE7QUFHQSxvQkFBQSxhQUhBO0FBSUEsaUJBQUE7QUFDQSx5QkFBQSxxQkFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsYUFBQSxjQUFBLENBQUEsYUFBQSxNQUFBLEVBQUEsYUFBQSxTQUFBLENBQUE7QUFDQTtBQUhBO0FBSkEsS0FBQTs7QUFXQSxtQkFBQSxLQUFBLENBQUEsY0FBQSxFQUFBO0FBQ0EsYUFBQSxjQURBO0FBRUEscUJBQUEsMkJBRkE7QUFHQSxvQkFBQTtBQUhBLEtBQUE7O0FBTUEsbUJBQUEsS0FBQSxDQUFBLHNCQUFBLEVBQUE7QUFDQSxhQUFBLGlCQURBO0FBRUEscUJBQUEsOEJBRkE7QUFHQSxvQkFBQTtBQUhBLEtBQUE7O0FBTUEsbUJBQUEsS0FBQSxDQUFBLG9CQUFBLEVBQUE7QUFDQSxhQUFBLGNBREE7QUFFQSxxQkFBQSxxQkFGQTtBQUdBLG9CQUFBO0FBSEEsS0FBQTtBQU9BLENBekVBO0FDQUEsSUFBQSxVQUFBLENBQUEsYUFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFlBQUEsRUFBQSxZQUFBLEVBQUEsWUFBQSxFQUFBLFdBQUEsRUFBQSxTQUFBLEVBQUE7O0FBRUEsV0FBQSxZQUFBLEdBQUEsWUFBQTtBQUNBLFdBQUEsU0FBQSxHQUFBLEVBQUE7QUFDQSxXQUFBLFdBQUEsR0FBQSxZQUFBLENBQUEsQ0FBQTtBQUNBLFdBQUEsU0FBQSxHQUFBLGFBQUEsTUFBQTtBQUNBLFdBQUEsU0FBQSxHQUFBLGFBQUEsU0FBQTs7QUFFQSxhQUFBLFVBQUEsR0FBQTtBQUNBLGVBQUEsWUFBQSxDQUFBLE9BQUEsQ0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLGdCQUFBLE1BQUEsU0FBQSxNQUFBLGFBQUEsU0FBQSxFQUFBO0FBQ0EsdUJBQUEsU0FBQSxDQUFBLElBQUEsQ0FBQSxNQUFBLFFBQUEsQ0FBQTtBQUNBLHVCQUFBLFNBQUEsQ0FBQSxJQUFBLENBQUEsTUFBQSxRQUFBLENBQUEsRTtBQUNBO0FBQ0EsU0FMQTtBQU1BOztBQUVBOztBQUVBLGFBQUEsYUFBQSxHQUFBO0FBQ0EsZUFBQSxPQUFBLEdBQUEsRUFBQTtBQUNBLFlBQUEsUUFBQSxZQUFBLENBQUEsRUFBQSxDQUFBLENBQUE7QUFDQSxhQUFBLElBQUEsSUFBQSxJQUFBLEtBQUEsRUFBQTtBQUNBLG1CQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsSUFBQTtBQUNBO0FBQ0E7O0FBRUE7OztBQUlBLGFBQUEsVUFBQSxHQUFBOztBQUVBLGVBQUEsYUFBQSxHQUFBLEVBQUE7QUFDQSxlQUFBLFdBQUEsQ0FBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxZQUFBLEVBQUE7QUFDQSxpQkFBQSxJQUFBLElBQUEsSUFBQSxHQUFBLEVBQUE7QUFDQSwwQkFBQSxJQUFBLENBQUEsSUFBQSxJQUFBLENBQUE7QUFDQTtBQUNBLG1CQUFBLGFBQUEsQ0FBQSxJQUFBLENBQUEsU0FBQTtBQUNBLFNBTkE7QUFPQTs7O0FBR0E7Ozs7QUFJQSxXQUFBLElBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsS0FBQSxFQUFBLEdBQUEsRUFBQSxXQUFBLEVBQUE7QUFDQSxnQkFBQSxHQUFBLENBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxLQUFBLEVBQUEsR0FBQSxFQUFBLFdBQUE7QUFDQSxZQUFBLFlBQUEsT0FBQSxTQUFBLENBQUEsUUFBQSxDQUFBLENBQUE7QUFDQSxnQkFBQSxHQUFBLENBQUEsV0FBQSxFQUFBLE9BQUEsU0FBQTtBQUNBLGdCQUFBLEdBQUEsQ0FBQSxVQUFBLEVBQUEsU0FBQTs7QUFFQSxZQUFBLGdCQUFBLFVBQUEsSUFBQSxDQUFBO0FBQ0EsdUJBQUEsT0FBQSxpQkFEQTtBQUVBLHlCQUFBLDZCQUZBO0FBR0Esd0JBQUEsa0JBSEE7QUFJQSxxQkFBQTtBQUNBLDBCQUFBLGtCQUFBLFlBQUEsRUFBQTtBQUNBLDJCQUFBLGFBQUEsY0FBQSxDQUFBLE1BQUEsRUFBQSxTQUFBLENBQUE7QUFDQSxpQkFIQTtBQUlBLDJCQUFBLHFCQUFBO0FBQUEsMkJBQUEsU0FBQTtBQUFBLGlCQUpBO0FBS0EsdUJBQUEsaUJBQUE7QUFBQSwyQkFBQSxHQUFBO0FBQUEsaUJBTEE7QUFNQSw0QkFBQSxzQkFBQTtBQUFBLDJCQUFBLFdBQUE7QUFBQTtBQU5BO0FBSkEsU0FBQSxDQUFBOztBQWNBLHNCQUFBLE1BQUEsQ0FBQSxJQUFBLENBQUEsWUFBQTtBQUNBLG9CQUFBLEdBQUEsQ0FBQSxRQUFBO0FBQ0EsbUJBQUEsVUFBQTtBQUNBLFNBSEE7QUFJQSxLQXhCQTs7QUEwQkEsV0FBQSxlQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsaUJBQUEsR0FBQSxDQUFBLE9BQUEsaUJBQUE7QUFDQSxLQUZBOztBQUlBLFdBQUEsTUFBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQTtBQUNBLHFCQUFBLFNBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUNBLElBREEsQ0FDQSxVQUFBLE1BQUEsRUFBQTtBQUNBLG9CQUFBLEdBQUEsQ0FBQSxNQUFBO0FBQ0EsbUJBQUEsYUFBQSxHQUFBLE1BQUE7QUFDQSxtQkFBQSxVQUFBO0FBQ0EsU0FMQTtBQU1BLEtBUEE7OztBQVVBLFdBQUEsVUFBQSxHQUFBLEtBQUE7QUFDQSxXQUFBLFlBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxVQUFBLEdBQUEsQ0FBQSxPQUFBLFVBQUE7QUFDQSxLQUZBOztBQUlBLFdBQUEsY0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQSxhQUFBLEVBQUE7QUFDQSxzQkFBQSxPQUFBLENBQUEsVUFBQSxHQUFBLEVBQUE7QUFDQSxnQkFBQSxJQUFBLFFBQUEsRUFBQTtBQUNBLDZCQUFBLFNBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLElBQUEsQ0FBQSxDQUFBLEVBQ0EsSUFEQSxDQUNBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsMkJBQUEsV0FBQSxHQUFBLE1BQUE7QUFDQTtBQUNBLGlCQUpBO0FBS0E7QUFDQSxTQVJBO0FBU0EsZUFBQSxVQUFBLEdBQUEsS0FBQTtBQUNBLEtBWEE7O0FBYUEsV0FBQSxTQUFBLEdBQUEsVUFBQSxhQUFBLEVBQUE7QUFDQSxZQUFBLE9BQUEsV0FBQSxFQUFBO0FBQ0EsMEJBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsUUFBQSxHQUFBLElBQUE7QUFDQSxhQUZBO0FBR0EsU0FKQSxNQUlBO0FBQ0EsMEJBQUEsT0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBO0FBQ0Esb0JBQUEsUUFBQSxHQUFBLEtBQUE7QUFDQSxhQUZBO0FBR0E7QUFDQSxLQVZBOztBQVlBLFdBQUEsZ0JBQUEsR0FBQSxVQUFBLGFBQUEsRUFBQTtBQUNBLFlBQUEsT0FBQSxXQUFBLEtBQUEsSUFBQSxFQUFBO0FBQ0EsbUJBQUEsV0FBQSxHQUFBLEtBQUE7QUFDQTtBQUNBLEtBSkE7O0FBTUEsV0FBQSxTQUFBLEdBQUEsVUFBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLEdBQUEsRUFBQTtBQUNBLHFCQUFBLFNBQUEsQ0FBQSxFQUFBLEVBQUEsS0FBQSxFQUFBLEdBQUEsRUFDQSxJQURBLENBQ0EsVUFBQSxNQUFBLEVBQUE7QUFDQSxtQkFBQSxXQUFBLEdBQUEsTUFBQTtBQUNBO0FBQ0EsU0FKQTtBQUtBLEtBTkE7O0FBUUEsV0FBQSxHQUFBLEdBQUEsVUFBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLHdEQUFBLEVBQUEsQ0FBQSxLQUFBLENBQUE7QUFDQSxLQUZBO0FBSUEsQ0F4SUE7O0FDQUEsSUFBQSxVQUFBLENBQUEsa0JBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxpQkFBQSxFQUFBLFlBQUEsRUFBQSxXQUFBLEVBQUEsWUFBQSxFQUFBLE1BQUEsRUFBQSxRQUFBLEVBQUEsU0FBQSxFQUFBLEtBQUEsRUFBQSxVQUFBLEVBQUE7O0FBRUEsV0FBQSxNQUFBLEdBQUEsYUFBQSxNQUFBOztBQUVBLFdBQUEsV0FBQSxHQUFBLFFBQUE7O0FBRUEsV0FBQSxTQUFBLEdBQUEsU0FBQTs7QUFFQSxXQUFBLEtBQUEsR0FBQSxLQUFBOztBQUVBLFdBQUEsVUFBQSxHQUFBLFVBQUE7O0FBRUEsV0FBQSxXQUFBLEdBQUEsWUFBQTs7QUFFQSxlQUFBLE9BQUEsR0FBQSxLQUFBLEdBQUE7O0FBRUEsS0FKQTs7O0FBUUEsYUFBQSxhQUFBLEdBQUE7QUFDQSxlQUFBLE9BQUEsR0FBQSxFQUFBO0FBQ0EsWUFBQSxRQUFBLE9BQUEsV0FBQSxDQUFBLENBQUEsRUFBQSxDQUFBLENBQUE7O0FBR0EsYUFBQSxJQUFBLElBQUEsSUFBQSxLQUFBLEVBQUE7QUFDQSxnQkFBQSxTQUFBLFlBQUEsSUFBQSxTQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsSUFBQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTs7O0FBR0EsYUFBQSxVQUFBLEdBQUE7QUFDQSxlQUFBLGFBQUEsR0FBQSxFQUFB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aW5kb3cuYXBwID0gYW5ndWxhci5tb2R1bGUoJ0Z1bGxzdGFja0dlbmVyYXRlZEFwcCcsIFsnZnNhUHJlQnVpbHQnLCAndWkucm91dGVyJywgJ3VpLmJvb3RzdHJhcCcsICduZ0FuaW1hdGUnXSk7XG5cbmFwcC5jb25maWcoZnVuY3Rpb24gKCR1cmxSb3V0ZXJQcm92aWRlciwgJGxvY2F0aW9uUHJvdmlkZXIpIHtcbiAgICAvLyBUaGlzIHR1cm5zIG9mZiBoYXNoYmFuZyB1cmxzICgvI2Fib3V0KSBhbmQgY2hhbmdlcyBpdCB0byBzb21ldGhpbmcgbm9ybWFsICgvYWJvdXQpXG4gICAgJGxvY2F0aW9uUHJvdmlkZXIuaHRtbDVNb2RlKHRydWUpO1xuICAgIC8vIElmIHdlIGdvIHRvIGEgVVJMIHRoYXQgdWktcm91dGVyIGRvZXNuJ3QgaGF2ZSByZWdpc3RlcmVkLCBnbyB0byB0aGUgXCIvXCIgdXJsLlxuICAgICR1cmxSb3V0ZXJQcm92aWRlci5vdGhlcndpc2UoJy8nKTtcbiAgICAvLyBUcmlnZ2VyIHBhZ2UgcmVmcmVzaCB3aGVuIGFjY2Vzc2luZyBhbiBPQXV0aCByb3V0ZVxuICAgICR1cmxSb3V0ZXJQcm92aWRlci53aGVuKCcvYXV0aC86cHJvdmlkZXInLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKTtcbiAgICB9KTtcbn0pO1xuXG4vLyBUaGlzIGFwcC5ydW4gaXMgZm9yIGNvbnRyb2xsaW5nIGFjY2VzcyB0byBzcGVjaWZpYyBzdGF0ZXMuXG5hcHAucnVuKGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBdXRoU2VydmljZSwgJHN0YXRlKSB7XG5cbiAgICAvLyBUaGUgZ2l2ZW4gc3RhdGUgcmVxdWlyZXMgYW4gYXV0aGVudGljYXRlZCB1c2VyLlxuICAgIHZhciBkZXN0aW5hdGlvblN0YXRlUmVxdWlyZXNBdXRoID0gZnVuY3Rpb24gKHN0YXRlKSB7XG4gICAgICAgIHJldHVybiBzdGF0ZS5kYXRhICYmIHN0YXRlLmRhdGEuYXV0aGVudGljYXRlO1xuICAgIH07XG5cbiAgICAvLyAkc3RhdGVDaGFuZ2VTdGFydCBpcyBhbiBldmVudCBmaXJlZFxuICAgIC8vIHdoZW5ldmVyIHRoZSBwcm9jZXNzIG9mIGNoYW5naW5nIGEgc3RhdGUgYmVnaW5zLlxuICAgICRyb290U2NvcGUuJG9uKCckc3RhdGVDaGFuZ2VTdGFydCcsIGZ1bmN0aW9uIChldmVudCwgdG9TdGF0ZSwgdG9QYXJhbXMpIHtcblxuICAgICAgICBpZiAoIWRlc3RpbmF0aW9uU3RhdGVSZXF1aXJlc0F1dGgodG9TdGF0ZSkpIHtcbiAgICAgICAgICAgIC8vIFRoZSBkZXN0aW5hdGlvbiBzdGF0ZSBkb2VzIG5vdCByZXF1aXJlIGF1dGhlbnRpY2F0aW9uXG4gICAgICAgICAgICAvLyBTaG9ydCBjaXJjdWl0IHdpdGggcmV0dXJuLlxuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpKSB7XG4gICAgICAgICAgICAvLyBUaGUgdXNlciBpcyBhdXRoZW50aWNhdGVkLlxuICAgICAgICAgICAgLy8gU2hvcnQgY2lyY3VpdCB3aXRoIHJldHVybi5cbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIENhbmNlbCBuYXZpZ2F0aW5nIHRvIG5ldyBzdGF0ZS5cbiAgICAgICAgZXZlbnQucHJldmVudERlZmF1bHQoKTtcblxuICAgICAgICBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKS50aGVuKGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgICAvLyBJZiBhIHVzZXIgaXMgcmV0cmlldmVkLCB0aGVuIHJlbmF2aWdhdGUgdG8gdGhlIGRlc3RpbmF0aW9uXG4gICAgICAgICAgICAvLyAodGhlIHNlY29uZCB0aW1lLCBBdXRoU2VydmljZS5pc0F1dGhlbnRpY2F0ZWQoKSB3aWxsIHdvcmspXG4gICAgICAgICAgICAvLyBvdGhlcndpc2UsIGlmIG5vIHVzZXIgaXMgbG9nZ2VkIGluLCBnbyB0byBcImxvZ2luXCIgc3RhdGUuXG4gICAgICAgICAgICBpZiAodXNlcikge1xuICAgICAgICAgICAgICAgICRzdGF0ZS5nbyh0b1N0YXRlLm5hbWUsIHRvUGFyYW1zKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgJHN0YXRlLmdvKCdsb2dpbicpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcblxuICAgIH0pO1xuXG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG5cbiAgICAvLyBSZWdpc3RlciBvdXIgKmFib3V0KiBzdGF0ZS5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnYWJvdXQnLCB7XG4gICAgICAgIHVybDogJy9hYm91dCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdBYm91dENvbnRyb2xsZXInLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2Fib3V0L2Fib3V0Lmh0bWwnXG4gICAgfSk7XG5cbn0pO1xuXG5hcHAuY29udHJvbGxlcignQWJvdXRDb250cm9sbGVyJywgZnVuY3Rpb24gKCRzY29wZSwgRnVsbHN0YWNrUGljcykge1xuXG4gICAgLy8gSW1hZ2VzIG9mIGJlYXV0aWZ1bCBGdWxsc3RhY2sgcGVvcGxlLlxuICAgICRzY29wZS5pbWFnZXMgPSBfLnNodWZmbGUoRnVsbHN0YWNrUGljcyk7XG5cbn0pOyIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2RvY3MnLCB7XG4gICAgICAgIHVybDogJy9kb2NzJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9kb2NzL2RvY3MuaHRtbCdcbiAgICB9KTtcbn0pO1xuIiwiKGZ1bmN0aW9uICgpIHtcblxuICAgICd1c2Ugc3RyaWN0JztcblxuICAgIC8vIEhvcGUgeW91IGRpZG4ndCBmb3JnZXQgQW5ndWxhciEgRHVoLWRveS5cbiAgICBpZiAoIXdpbmRvdy5hbmd1bGFyKSB0aHJvdyBuZXcgRXJyb3IoJ0kgY2FuXFwndCBmaW5kIEFuZ3VsYXIhJyk7XG5cbiAgICB2YXIgYXBwID0gYW5ndWxhci5tb2R1bGUoJ2ZzYVByZUJ1aWx0JywgW10pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ1NvY2tldCcsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKCF3aW5kb3cuaW8pIHRocm93IG5ldyBFcnJvcignc29ja2V0LmlvIG5vdCBmb3VuZCEnKTtcbiAgICAgICAgcmV0dXJuIHdpbmRvdy5pbyh3aW5kb3cubG9jYXRpb24ub3JpZ2luKTtcbiAgICB9KTtcblxuICAgIC8vIEFVVEhfRVZFTlRTIGlzIHVzZWQgdGhyb3VnaG91dCBvdXIgYXBwIHRvXG4gICAgLy8gYnJvYWRjYXN0IGFuZCBsaXN0ZW4gZnJvbSBhbmQgdG8gdGhlICRyb290U2NvcGVcbiAgICAvLyBmb3IgaW1wb3J0YW50IGV2ZW50cyBhYm91dCBhdXRoZW50aWNhdGlvbiBmbG93LlxuICAgIGFwcC5jb25zdGFudCgnQVVUSF9FVkVOVFMnLCB7XG4gICAgICAgIGxvZ2luU3VjY2VzczogJ2F1dGgtbG9naW4tc3VjY2VzcycsXG4gICAgICAgIGxvZ2luRmFpbGVkOiAnYXV0aC1sb2dpbi1mYWlsZWQnLFxuICAgICAgICBsb2dvdXRTdWNjZXNzOiAnYXV0aC1sb2dvdXQtc3VjY2VzcycsXG4gICAgICAgIHNlc3Npb25UaW1lb3V0OiAnYXV0aC1zZXNzaW9uLXRpbWVvdXQnLFxuICAgICAgICBub3RBdXRoZW50aWNhdGVkOiAnYXV0aC1ub3QtYXV0aGVudGljYXRlZCcsXG4gICAgICAgIG5vdEF1dGhvcml6ZWQ6ICdhdXRoLW5vdC1hdXRob3JpemVkJ1xuICAgIH0pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ0F1dGhJbnRlcmNlcHRvcicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCAkcSwgQVVUSF9FVkVOVFMpIHtcbiAgICAgICAgdmFyIHN0YXR1c0RpY3QgPSB7XG4gICAgICAgICAgICA0MDE6IEFVVEhfRVZFTlRTLm5vdEF1dGhlbnRpY2F0ZWQsXG4gICAgICAgICAgICA0MDM6IEFVVEhfRVZFTlRTLm5vdEF1dGhvcml6ZWQsXG4gICAgICAgICAgICA0MTk6IEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LFxuICAgICAgICAgICAgNDQwOiBBVVRIX0VWRU5UUy5zZXNzaW9uVGltZW91dFxuICAgICAgICB9O1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KHN0YXR1c0RpY3RbcmVzcG9uc2Uuc3RhdHVzXSwgcmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVzcG9uc2UpXG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgfSk7XG5cbiAgICBhcHAuY29uZmlnKGZ1bmN0aW9uICgkaHR0cFByb3ZpZGVyKSB7XG4gICAgICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goW1xuICAgICAgICAgICAgJyRpbmplY3RvcicsXG4gICAgICAgICAgICBmdW5jdGlvbiAoJGluamVjdG9yKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRpbmplY3Rvci5nZXQoJ0F1dGhJbnRlcmNlcHRvcicpO1xuICAgICAgICAgICAgfVxuICAgICAgICBdKTtcbiAgICB9KTtcblxuICAgIGFwcC5zZXJ2aWNlKCdBdXRoU2VydmljZScsIGZ1bmN0aW9uICgkaHR0cCwgU2Vzc2lvbiwgJHJvb3RTY29wZSwgQVVUSF9FVkVOVFMsICRxKSB7XG5cbiAgICAgICAgZnVuY3Rpb24gb25TdWNjZXNzZnVsTG9naW4ocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHZhciBkYXRhID0gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgICAgIFNlc3Npb24uY3JlYXRlKGRhdGEuaWQsIGRhdGEudXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3QoQVVUSF9FVkVOVFMubG9naW5TdWNjZXNzKTtcbiAgICAgICAgICAgIHJldHVybiBkYXRhLnVzZXI7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBVc2VzIHRoZSBzZXNzaW9uIGZhY3RvcnkgdG8gc2VlIGlmIGFuXG4gICAgICAgIC8vIGF1dGhlbnRpY2F0ZWQgdXNlciBpcyBjdXJyZW50bHkgcmVnaXN0ZXJlZC5cbiAgICAgICAgdGhpcy5pc0F1dGhlbnRpY2F0ZWQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gISFTZXNzaW9uLnVzZXI7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5nZXRMb2dnZWRJblVzZXIgPSBmdW5jdGlvbiAoZnJvbVNlcnZlcikge1xuXG4gICAgICAgICAgICAvLyBJZiBhbiBhdXRoZW50aWNhdGVkIHNlc3Npb24gZXhpc3RzLCB3ZVxuICAgICAgICAgICAgLy8gcmV0dXJuIHRoZSB1c2VyIGF0dGFjaGVkIHRvIHRoYXQgc2Vzc2lvblxuICAgICAgICAgICAgLy8gd2l0aCBhIHByb21pc2UuIFRoaXMgZW5zdXJlcyB0aGF0IHdlIGNhblxuICAgICAgICAgICAgLy8gYWx3YXlzIGludGVyZmFjZSB3aXRoIHRoaXMgbWV0aG9kIGFzeW5jaHJvbm91c2x5LlxuXG4gICAgICAgICAgICAvLyBPcHRpb25hbGx5LCBpZiB0cnVlIGlzIGdpdmVuIGFzIHRoZSBmcm9tU2VydmVyIHBhcmFtZXRlcixcbiAgICAgICAgICAgIC8vIHRoZW4gdGhpcyBjYWNoZWQgdmFsdWUgd2lsbCBub3QgYmUgdXNlZC5cblxuICAgICAgICAgICAgaWYgKHRoaXMuaXNBdXRoZW50aWNhdGVkKCkgJiYgZnJvbVNlcnZlciAhPT0gdHJ1ZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS53aGVuKFNlc3Npb24udXNlcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIE1ha2UgcmVxdWVzdCBHRVQgL3Nlc3Npb24uXG4gICAgICAgICAgICAvLyBJZiBpdCByZXR1cm5zIGEgdXNlciwgY2FsbCBvblN1Y2Nlc3NmdWxMb2dpbiB3aXRoIHRoZSByZXNwb25zZS5cbiAgICAgICAgICAgIC8vIElmIGl0IHJldHVybnMgYSA0MDEgcmVzcG9uc2UsIHdlIGNhdGNoIGl0IGFuZCBpbnN0ZWFkIHJlc29sdmUgdG8gbnVsbC5cbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9zZXNzaW9uJykudGhlbihvblN1Y2Nlc3NmdWxMb2dpbikuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLnNpZ251cCA9IGZ1bmN0aW9uKGNyZWRlbnRpYWxzKXtcbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvc2lnbnVwJywgY3JlZGVudGlhbHMpXG4gICAgICAgICAgICAudGhlbihvblN1Y2Nlc3NmdWxMb2dpbilcbiAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdCh7IG1lc3NhZ2U6ICdJbnZhbGlkIHNpZ251cCBjcmVkZW50aWFscy4nIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5sb2dpbiA9IGZ1bmN0aW9uIChjcmVkZW50aWFscykge1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9sb2dpbicsIGNyZWRlbnRpYWxzKVxuICAgICAgICAgICAgICAgIC50aGVuKG9uU3VjY2Vzc2Z1bExvZ2luKVxuICAgICAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QoeyBtZXNzYWdlOiAnSW52YWxpZCBsb2dpbiBjcmVkZW50aWFscy4nIH0pO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2xvZ291dCcpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIFNlc3Npb24uZGVzdHJveSgpO1xuICAgICAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChBVVRIX0VWRU5UUy5sb2dvdXRTdWNjZXNzKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuXG4gICAgfSk7XG5cbiAgICBhcHAuc2VydmljZSgnU2Vzc2lvbicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBVVRIX0VWRU5UUykge1xuXG4gICAgICAgIHZhciBzZWxmID0gdGhpcztcblxuICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5ub3RBdXRoZW50aWNhdGVkLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBzZWxmLmRlc3Ryb3koKTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHNlbGYuZGVzdHJveSgpO1xuICAgICAgICB9KTtcblxuICAgICAgICB0aGlzLmlkID0gbnVsbDtcbiAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcblxuICAgICAgICB0aGlzLmNyZWF0ZSA9IGZ1bmN0aW9uIChzZXNzaW9uSWQsIHVzZXIpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBzZXNzaW9uSWQ7XG4gICAgICAgICAgICB0aGlzLnVzZXIgPSB1c2VyO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMuZGVzdHJveSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBudWxsO1xuICAgICAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcbiAgICAgICAgfTtcblxuICAgIH0pO1xuXG59KSgpO1xuIiwiYXBwLmNvbnRyb2xsZXIoJ0NyZWF0ZWRiQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsICRzdGF0ZSwgQ3JlYXRlZGJGYWN0b3J5KSB7XG5cblx0JHNjb3BlLmNyZWF0ZWREQiA9IGZhbHNlO1xuICAgICAgICAkc2NvcGUuY29sdW1uQXJyYXkgPSBbXTtcblxuXHQkc2NvcGUuYWRkID0gZnVuY3Rpb24oKSB7XG5cdFx0JHNjb3BlLmNvbHVtbkFycmF5LnB1c2goJzEnKTtcblx0fVxuXG5cdCRzY29wZS5jcmVhdGVEQiA9IGZ1bmN0aW9uKG5hbWUpIHtcblx0XHRDcmVhdGVkYkZhY3RvcnkuY3JlYXRlREIobmFtZSlcblx0XHQudGhlbihmdW5jdGlvbihkYXRhKSB7XG5cdFx0XHQkc2NvcGUuY3JlYXRlZERCID0gZGF0YTtcblx0XHR9KVxuXHR9XG5cblx0JHNjb3BlLmNyZWF0ZVRhYmxlID0gZnVuY3Rpb24odGFibGUsIERCKXtcblx0XHRDcmVhdGVkYkZhY3RvcnkuY3JlYXRlVGFibGUodGFibGUsIERCKVxuXHRcdFx0JHN0YXRlLmdvKCdUYWJsZScsIHtkYk5hbWU6ICRzY29wZS5jcmVhdGVkREIuZGJOYW1lfSwge3JlbG9hZDp0cnVlfSlcblx0fVxufSk7XG4iLCJhcHAuZmFjdG9yeSgnQ3JlYXRlZGJGYWN0b3J5JywgZnVuY3Rpb24gKCRodHRwKSB7XG5cblx0dmFyIENyZWF0ZWRiRmFjdG9yeSA9IHt9O1xuXG5cdGZ1bmN0aW9uIHJlc1RvRGF0YShyZXMpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5kYXRhO1xuICAgIH1cblxuICAgIENyZWF0ZWRiRmFjdG9yeS5jcmVhdGVEQiA9IGZ1bmN0aW9uKGRiTmFtZSkge1xuICAgIFx0cmV0dXJuICRodHRwLnBvc3QoJy9hcGkvbWFzdGVyZGInLCBkYk5hbWUpXG4gICAgXHQudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICBDcmVhdGVkYkZhY3RvcnkuY3JlYXRlVGFibGUgPSBmdW5jdGlvbih0YWJsZSwgY3JlYXRlZERCKSB7XG4gICAgdGFibGUuZGJOYW1lID0gY3JlYXRlZERCLmRiTmFtZTtcbiAgICByZXR1cm4gJGh0dHAucG9zdCgnL2FwaS9jbGllbnRkYicsIHRhYmxlKVxuICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICB9XG5cblx0cmV0dXJuIENyZWF0ZWRiRmFjdG9yeTsgXG59KVxuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnY3JlYXRlZGInLCB7XG4gICAgICAgIHVybDogJy9jcmVhdGVkYicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvY3JlYXRlZGIvY3JlYXRlZGIuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdDcmVhdGVkYkN0cmwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgIFx0bG9nZ2VkSW5Vc2VyOiBmdW5jdGlvbihBdXRoU2VydmljZSkge1xuICAgICAgICBcdFx0cmV0dXJuIEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpO1xuICAgICAgICBcdH1cbiAgICAgICAgfVxuICAgIH0pO1xuXG59KTsiLCJhcHAuY29udHJvbGxlcignSG9tZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBhbGxEYnMsICRzdGF0ZSkge1xuXG5cdCRzY29wZS5hbGxEYnMgPSBhbGxEYnM7XG59KTtcbiIsImFwcC5mYWN0b3J5KCdIb21lRmFjdG9yeScsIGZ1bmN0aW9uICgkaHR0cCkge1xuXG5cdHZhciBIb21lRmFjdG9yeSA9IHt9O1xuXG5cdGZ1bmN0aW9uIHJlc1RvRGF0YShyZXMpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5kYXRhO1xuICAgIH1cblxuICAgIEhvbWVGYWN0b3J5LmdldEFsbERicyA9IGZ1bmN0aW9uKCl7XG4gICAgXHRyZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL21hc3RlcmRiJylcbiAgICBcdC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgICBIb21lRmFjdG9yeS5kZWxldGVEQiA9IGZ1bmN0aW9uKG5hbWUpe1xuICAgIFx0cmV0dXJuICRodHRwLmRlbGV0ZSgnL2FwaS9tYXN0ZXJkYi8nICsgbmFtZSlcbiAgICBcdC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cblx0cmV0dXJuIEhvbWVGYWN0b3J5OyBcbn0pIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnSG9tZScsIHtcbiAgICAgICAgdXJsOiAnL2hvbWUnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2hvbWUvaG9tZS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0hvbWVDdHJsJyxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICBcdGFsbERiczogZnVuY3Rpb24oSG9tZUZhY3Rvcnkpe1xuICAgICAgICBcdFx0cmV0dXJuIEhvbWVGYWN0b3J5LmdldEFsbERicygpO1xuICAgICAgICBcdH0sXG4gICAgICAgICAgICBsb2dnZWRJblVzZXI6IGZ1bmN0aW9uIChBdXRoU2VydmljZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pO1xufSk7IiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnbGFuZGluZ1BhZ2UnLCB7XG4gICAgICAgIHVybDogJy8nLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2xhbmRpbmdQYWdlL2xhbmRpbmdQYWdlLmh0bWwnXG4gICAgICAgIH1cbiAgICApO1xuXG59KTsiLCJhcHAuY29uZmlnKGZ1bmN0aW9uKCRzdGF0ZVByb3ZpZGVyKSB7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnbG9naW4nLCB7XG4gICAgICAgIHVybDogJy9sb2dpbicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvbG9naW4vbG9naW4uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdMb2dpbkN0cmwnXG4gICAgfSk7XG5cbn0pO1xuXG5hcHAuY29udHJvbGxlcignTG9naW5DdHJsJywgZnVuY3Rpb24oJHNjb3BlLCBBdXRoU2VydmljZSwgJHN0YXRlKSB7XG5cbiAgICAkc2NvcGUubG9naW4gPSB7fTtcbiAgICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICAgJHNjb3BlLnNlbmRMb2dpbiA9IGZ1bmN0aW9uKGxvZ2luSW5mbykge1xuXG4gICAgICAgICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgICAgICAgQXV0aFNlcnZpY2UubG9naW4obG9naW5JbmZvKS50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKCdIb21lJyk7XG4gICAgICAgIH0pLmNhdGNoKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgJHNjb3BlLmVycm9yID0gJ0ludmFsaWQgbG9naW4gY3JlZGVudGlhbHMuJztcbiAgICAgICAgfSk7XG5cbiAgICB9O1xuXG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnbWVtYmVyc09ubHknLCB7XG4gICAgICAgIHVybDogJy9tZW1iZXJzLWFyZWEnLFxuICAgICAgICB0ZW1wbGF0ZTogJzxpbWcgbmctcmVwZWF0PVwiaXRlbSBpbiBzdGFzaFwiIHdpZHRoPVwiMzAwXCIgbmctc3JjPVwie3sgaXRlbSB9fVwiIC8+JyxcbiAgICAgICAgY29udHJvbGxlcjogZnVuY3Rpb24gKCRzY29wZSwgU2VjcmV0U3Rhc2gpIHtcbiAgICAgICAgICAgIFNlY3JldFN0YXNoLmdldFN0YXNoKCkudGhlbihmdW5jdGlvbiAoc3Rhc2gpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuc3Rhc2ggPSBzdGFzaDtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9LFxuICAgICAgICAvLyBUaGUgZm9sbG93aW5nIGRhdGEuYXV0aGVudGljYXRlIGlzIHJlYWQgYnkgYW4gZXZlbnQgbGlzdGVuZXJcbiAgICAgICAgLy8gdGhhdCBjb250cm9scyBhY2Nlc3MgdG8gdGhpcyBzdGF0ZS4gUmVmZXIgdG8gYXBwLmpzLlxuICAgICAgICBkYXRhOiB7XG4gICAgICAgICAgICBhdXRoZW50aWNhdGU6IHRydWVcbiAgICAgICAgfVxuICAgIH0pO1xuXG59KTtcblxuYXBwLmZhY3RvcnkoJ1NlY3JldFN0YXNoJywgZnVuY3Rpb24gKCRodHRwKSB7XG5cbiAgICB2YXIgZ2V0U3Rhc2ggPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvbWVtYmVycy9zZWNyZXQtc3Rhc2gnKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmRhdGE7XG4gICAgICAgIH0pO1xuICAgIH07XG5cbiAgICByZXR1cm4ge1xuICAgICAgICBnZXRTdGFzaDogZ2V0U3Rhc2hcbiAgICB9O1xuXG59KTsiLCIndXNlIHN0cmljdCc7XG5cbmFwcC5kaXJlY3RpdmUoJ29hdXRoQnV0dG9uJywgZnVuY3Rpb24gKCkge1xuICByZXR1cm4ge1xuICAgIHNjb3BlOiB7XG4gICAgICBwcm92aWRlck5hbWU6ICdAJ1xuICAgIH0sXG4gICAgcmVzdHJpY3Q6ICdFJyxcbiAgICB0ZW1wbGF0ZVVybDogJy9qcy9vYXV0aC9vYXV0aC1idXR0b24uaHRtbCdcbiAgfVxufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ3NpZ251cCcsIHtcbiAgICAgICAgdXJsOiAnL3NpZ251cCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvc2lnbnVwL3NpZ251cC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1NpZ251cEN0cmwnXG4gICAgfSk7XG5cbn0pO1xuXG5hcHAuY29udHJvbGxlcignU2lnbnVwQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsIEF1dGhTZXJ2aWNlLCAkc3RhdGUpIHtcblxuICAgICRzY29wZS5zaWdudXAgPSB7fTtcbiAgICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICAgJHNjb3BlLnNlbmRTaWdudXAgPSBmdW5jdGlvbiAoc2lnbnVwSW5mbykge1xuICAgICAgICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuICAgICAgICBBdXRoU2VydmljZS5zaWdudXAoc2lnbnVwSW5mbykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oJ2hvbWUnKTtcbiAgICAgICAgfSkuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgJHNjb3BlLmVycm9yID0gJ09vcHMsIGNhbm5vdCBzaWduIHVwIHdpdGggdGhvc2UgY3JlZGVudGlhbHMuJztcbiAgICAgICAgfSk7XG5cbiAgICB9O1xuXG59KTtcbiIsImFwcC5jb250cm9sbGVyKCdBc3NvY2lhdGlvbkluc3RhbmNlQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsICR1aWJNb2RhbEluc3RhbmNlLCBmb3JlaWduQ29scywgVGFibGVGYWN0b3J5LCBIb21lRmFjdG9yeSwgJHN0YXRlUGFyYW1zLCAkc3RhdGUsIGZvclRhYmxlLCBmb3JUYWJsZU5hbWUsIGN1cnJUYWJsZSwgY29sTmFtZSwgaWQxKSB7XG5cbiAgJHNjb3BlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG5cbiAgJHNjb3BlLnNpbmdsZVRhYmxlID0gZm9yVGFibGU7XG5cbiAgJHNjb3BlLlRhYmxlTmFtZSA9IGZvclRhYmxlTmFtZTtcblxuICAkc2NvcGUuY3VyclRhYmxlID0gY3VyclRhYmxlO1xuXG4gICRzY29wZS5jb2xOYW1lID0gY29sTmFtZTtcblxuICAkc2NvcGUuaWQxID0gaWQxO1xuXG4gICRzY29wZS5zZXRTZWxlY3RlZCA9IGZ1bmN0aW9uKCl7XG5cbiAgICAkc2NvcGUuY3VyclJvdyA9IHRoaXMucm93O1xuICAgIGNvbnNvbGUubG9nKCRzY29wZS5jdXJyUm93KTtcbiAgfVxuXG4gXG5cbiAgZnVuY3Rpb24gQ3JlYXRlQ29sdW1ucygpe1xuICAgICRzY29wZS5jb2x1bW5zID0gW107XG4gICAgdmFyIHRhYmxlID0gZm9yVGFibGVbMF07XG5cblxuICAgIGZvcih2YXIgcHJvcCBpbiB0YWJsZSl7XG4gICAgICBpZihwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKXtcbiAgICAgICAgJHNjb3BlLmNvbHVtbnMucHVzaChwcm9wKTsgIFxuICAgICAgfSBcbiAgICB9XG4gIH1cblxuICAgIENyZWF0ZUNvbHVtbnMoKTtcblxuXG4gICAgLy90aGlzIGZ1bmN0aW9uIHdpbGwgcmUgcnVuIHdoZW4gdGhlIGZpbHRlciBmdW5jdGlvbiBpcyBpbnZva2VkLCBpbiBvcmRlciB0byByZXBvcHVsYXRlIHRoZSB0YWJsZVxuICAgIGZ1bmN0aW9uIENyZWF0ZVJvd3MoKSB7XG4gICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5ID0gW107XG4gICAgICAgIGZvclRhYmxlLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICB2YXIgcm93VmFsdWVzID0gW107XG4gICAgICAgICAgICBmb3IgKHZhciBwcm9wIGluIHJvdykge1xuICAgICAgICAgICAgICAgIGlmIChwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKSByb3dWYWx1ZXMucHVzaChyb3dbcHJvcF0pXG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheS5wdXNoKHJvd1ZhbHVlcylcbiAgICAgICAgfSlcbiAgICB9XG5cbiAgICAvLyBTb3J0IHRoZSB2YWx1ZXMgaW4gc2luZ2xlVGFibGUgc28gdGhhdCBhbGwgdGhlIHZhbHVlcyBmb3IgYSBnaXZlbiByb3cgYXJlIGdyb3VwZWRcbiAgICBDcmVhdGVSb3dzKCk7XG5cblxuICAkc2NvcGUuc2V0Rm9yZWlnbktleSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGJsTmFtZSwgY29sTmFtZSwgaWQxLCBpZDIpe1xuICAgICR1aWJNb2RhbEluc3RhbmNlLmNsb3NlKCk7XG4gICAgVGFibGVGYWN0b3J5LnNldEZvcmVpZ25LZXkoZGJOYW1lLCB0YmxOYW1lLCBjb2xOYW1lLCBpZDEsIGlkMilcbiAgICAudGhlbihmdW5jdGlvbigpe1xuICAgICAgICAkc3RhdGUuZ28oJ1RhYmxlLlNpbmdsZScsIHsgZGJOYW1lOiAkc2NvcGUuZGJOYW1lLCB0YWJsZU5hbWU6ICRzY29wZS5jdXJyVGFibGUgfSwgeyByZWxvYWQ6IHRydWUgfSlcbiAgICB9KVxuICB9XG5cblxuXG4gICRzY29wZS5vayA9IGZ1bmN0aW9uICgpIHtcbiAgICAkdWliTW9kYWxJbnN0YW5jZS5jbG9zZSgkc2NvcGUuc2VsZWN0ZWQuaXRlbSk7XG4gIH07XG5cbiAgJHNjb3BlLmNhbmNlbCA9IGZ1bmN0aW9uICgpIHtcbiAgICAkdWliTW9kYWxJbnN0YW5jZS5kaXNtaXNzKCdjYW5jZWwnKTtcbiAgfTtcbn0pOyIsImFwcC5jb250cm9sbGVyKCdkZWxldGVEQkN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCAkdWliTW9kYWwsICRsb2cpIHtcblxuICAkc2NvcGUuaXRlbXMgPSBbJ2l0ZW0xJywgJ2l0ZW0yJywgJ2l0ZW0zJ107XG5cbiAgJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkID0gdHJ1ZTtcblxuICAkc2NvcGUub3BlbiA9IGZ1bmN0aW9uIChzaXplKSB7XG5cbiAgICB2YXIgbW9kYWxJbnN0YW5jZSA9ICR1aWJNb2RhbC5vcGVuKHtcbiAgICAgIGFuaW1hdGlvbjogJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkLFxuICAgICAgdGVtcGxhdGVVcmw6ICdkZWxldGVEQkNvbnRlbnQuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnZGVsZXRlREJJbnN0YW5jZUN0cmwnLFxuICAgICAgc2l6ZTogc2l6ZSxcbiAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgaXRlbXM6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICByZXR1cm4gJHNjb3BlLml0ZW1zO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICBtb2RhbEluc3RhbmNlLnJlc3VsdC50aGVuKGZ1bmN0aW9uIChzZWxlY3RlZEl0ZW0pIHtcbiAgICAgICRzY29wZS5zZWxlY3RlZCA9IHNlbGVjdGVkSXRlbTtcbiAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAkbG9nLmluZm8oJ01vZGFsIGRpc21pc3NlZCBhdDogJyArIG5ldyBEYXRlKCkpO1xuICAgIH0pO1xuICB9O1xuXG4gICRzY29wZS50b2dnbGVBbmltYXRpb24gPSBmdW5jdGlvbiAoKSB7XG4gICAgJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkID0gISRzY29wZS5hbmltYXRpb25zRW5hYmxlZDtcbiAgfTtcblxufSk7XG5cbmFwcC5jb250cm9sbGVyKCdkZWxldGVEQkluc3RhbmNlQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsICR1aWJNb2RhbEluc3RhbmNlLCBpdGVtcywgVGFibGVGYWN0b3J5LCBIb21lRmFjdG9yeSwgJHN0YXRlUGFyYW1zLCAkc3RhdGUpIHtcblxuXG4gICRzY29wZS5kcm9wRGJUZXh0ID0gJ0RST1AgREFUQUJBU0UnXG4gICRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lO1xuXG4gICRzY29wZS5kZWxldGVUaGVEYiA9IGZ1bmN0aW9uKCl7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoJHNjb3BlLnNlbGVjdGVkLml0ZW0pO1xuICAgIFRhYmxlRmFjdG9yeS5kZWxldGVEYigkc2NvcGUuZGJOYW1lKVxuICAgIC50aGVuKGZ1bmN0aW9uKCl7XG4gICAgICBIb21lRmFjdG9yeS5kZWxldGVEQigkc2NvcGUuZGJOYW1lKVxuICAgIH0pXG4gICAgLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAkc3RhdGUuZ28oJ0hvbWUnLCB7fSwge3JlbG9hZCA6IHRydWV9KVxuICAgIH0pXG4gIH1cblxuICAkc2NvcGUuaXRlbXMgPSBpdGVtcztcbiAgJHNjb3BlLnNlbGVjdGVkID0ge1xuICAgIGl0ZW06ICRzY29wZS5pdGVtc1swXVxuICB9O1xuXG4gICRzY29wZS5vayA9IGZ1bmN0aW9uICgpIHtcbiAgICAkdWliTW9kYWxJbnN0YW5jZS5jbG9zZSgkc2NvcGUuc2VsZWN0ZWQuaXRlbSk7XG4gIH07XG5cbiAgJHNjb3BlLmNhbmNlbCA9IGZ1bmN0aW9uICgpIHtcbiAgICAkdWliTW9kYWxJbnN0YW5jZS5kaXNtaXNzKCdjYW5jZWwnKTtcbiAgfTtcbn0pOyIsImFwcC5jb250cm9sbGVyKCdEZWxldGVEYkN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlKSB7XG5cbiAgJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkID0gdHJ1ZTtcblxuICAkc2NvcGUub3BlbiA9IGZ1bmN0aW9uIChzaXplKSB7XG5cbiAgICB2YXIgbW9kYWxJbnN0YW5jZSA9ICR1aWJNb2RhbC5vcGVuKHtcbiAgICAgIGFuaW1hdGlvbjogJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkLFxuICAgICAgdGVtcGxhdGVVcmw6ICdkZWxldGVEYkNvbnRlbnQuaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAnRGVsZXRlRGJJbnN0YW5jZUN0cmwnLFxuICAgICAgc2l6ZTogc2l6ZSxcbiAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgaXRlbXM6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICByZXR1cm4gJHNjb3BlLml0ZW1zO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICBtb2RhbEluc3RhbmNlLnJlc3VsdC50aGVuKGZ1bmN0aW9uIChzZWxlY3RlZEl0ZW0pIHtcbiAgICAgICRzY29wZS5zZWxlY3RlZCA9IHNlbGVjdGVkSXRlbTtcbiAgICB9LCBmdW5jdGlvbiAoKSB7XG4gICAgICAkbG9nLmluZm8oJ01vZGFsIGRpc21pc3NlZCBhdDogJyArIG5ldyBEYXRlKCkpO1xuICAgIH0pO1xuICB9O1xuXG59KTtcblxuXG5hcHAuY29udHJvbGxlcignRGVsZXRlRGJJbnN0YW5jZUN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCAkdWliTW9kYWxJbnN0YW5jZSwgaXRlbXMsICRzdGF0ZVBhcmFtcywgVGFibGVGYWN0b3J5KSB7XG5cbiAgJHNjb3BlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWVcblxuICAkc2NvcGUuZHJvcERhdGFiYXNlID0gJ0RST1AgREFUQUJBU0UnXG5cbiAgJHNjb3BlLmRlbGV0ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICBUYWJsZUZhY3RvcnkuZGVsZXRlRGIoJHNjb3BlLmRiTmFtZSlcbiAgICAkc3RhdGUuZ28oJ0hvbWUnLCB7fSwge3JlbG9hZCA6IHRydWV9KVxuICB9O1xuXG4gICRzY29wZS5jYW5jZWwgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHVpYk1vZGFsSW5zdGFuY2UuZGlzbWlzcygnY2FuY2VsJyk7XG4gIH07XG59KTsiLCJhcHAuY29udHJvbGxlcignSm9pblRhYmxlQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsIFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zLCBqb2luVGFibGUpIHtcblxuICAgICRzY29wZS5qb2luVGFibGUgPSBqb2luVGFibGU7XG5cblxuXHRmdW5jdGlvbiBDcmVhdGVDb2x1bW5zKCl7XG5cdFx0JHNjb3BlLmNvbHVtbnMgPSBbXTtcblx0XHR2YXIgdGFibGUgPSAkc2NvcGUuam9pblRhYmxlWzBdO1xuXG5cblx0XHRmb3IodmFyIHByb3AgaW4gdGFibGUpe1xuXHRcdFx0aWYocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jyl7XG5cdFx0XHRcdCRzY29wZS5jb2x1bW5zLnB1c2gocHJvcCk7XHRcblx0XHRcdH0gXG5cdFx0fVxuXHR9XG5cbiAgICBDcmVhdGVDb2x1bW5zKCk7XG5cblxuICAgIC8vdGhpcyBmdW5jdGlvbiB3aWxsIHJlIHJ1biB3aGVuIHRoZSBmaWx0ZXIgZnVuY3Rpb24gaXMgaW52b2tlZCwgaW4gb3JkZXIgdG8gcmVwb3B1bGF0ZSB0aGUgdGFibGVcbiAgICBmdW5jdGlvbiBDcmVhdGVSb3dzKCkge1xuICAgIFx0dmFyIGFsaWFzO1xuICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheSA9IFtdO1xuICAgICAgICBqb2luVGFibGUuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIHZhciByb3dWYWx1ZXMgPSBbXTtcbiAgICAgICAgICAgIGZvciAodmFyIHByb3AgaW4gcm93KSB7XG4gICAgICAgICAgICAgICAgaWYgKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpIHJvd1ZhbHVlcy5wdXNoKHJvd1twcm9wXSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5LnB1c2gocm93VmFsdWVzKVxuICAgICAgICB9KVxuICAgIH1cblxuICAgIC8vIFNvcnQgdGhlIHZhbHVlcyBpbiBzaW5nbGVUYWJsZSBzbyB0aGF0IGFsbCB0aGUgdmFsdWVzIGZvciBhIGdpdmVuIHJvdyBhcmUgZ3JvdXBlZFxuICAgIENyZWF0ZVJvd3MoKTtcblxuXG59KSIsImFwcC5jb250cm9sbGVyKCdRdWVyeVRhYmxlQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsIFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG5cbiAgICAkc2NvcGUucUZpbHRlciA9IGZ1bmN0aW9uKHJlZmVyZW5jZVN0cmluZywgdmFsKXtcbiAgICAgICAgaWYoIXJlZmVyZW5jZVN0cmluZykgcmV0dXJuIHRydWU7XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgZm9yKHZhciBwcm9wIGluIHZhbCl7XG4gICAgICAgICAgICAgICAgdmFyIGNlbGxWYWwgPSB2YWxbcHJvcF0udG9TdHJpbmcoKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgICAgICAgIHZhciBzZWFyY2hWYWwgPSByZWZlcmVuY2VTdHJpbmcudG9TdHJpbmcoKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKGNlbGxWYWwsIHNlYXJjaFZhbCwgY2VsbFZhbC5pbmRleE9mKHNlYXJjaFZhbCkgIT09IC0xKVxuICAgICAgICAgICAgICAgIGlmKGNlbGxWYWwuaW5kZXhPZihzZWFyY2hWYWwpICE9PSAtMSkgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxufSkiLCJhcHAuY29udHJvbGxlcignU2luZ2xlVGFibGVDdHJsJywgZnVuY3Rpb24oJHNjb3BlLCBUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcywgc2luZ2xlVGFibGUsICR3aW5kb3csICRzdGF0ZSwgJHVpYk1vZGFsLCBhc3NvY2lhdGlvbnMsICRsb2cpIHtcblxuICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9QdXR0aW5nIHN0dWZmIG9uIHNjb3BlLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuXG4gICAgJHNjb3BlLnRoZURiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG4gICAgJHNjb3BlLnRoZVRhYmxlTmFtZSA9ICRzdGF0ZVBhcmFtcy50YWJsZU5hbWU7XG4gICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gc2luZ2xlVGFibGVbMF0uc29ydChmdW5jdGlvbihhLCBiKXtcbiAgICAgICAgaWYoYS5pZCA+IGIuaWQpIHJldHVybiAxO1xuICAgICAgICBpZihhLmlkIDwgYi5pZCkgcmV0dXJuIC0xO1xuICAgICAgICByZXR1cm4gMDtcbiAgICB9KTtcbiAgICAkc2NvcGUuc2VsZWN0ZWRBbGwgPSBmYWxzZTtcbiAgICAkc2NvcGUuYXNzb2NpYXRpb25zID0gYXNzb2NpYXRpb25zO1xuXG5cbiAgICBpZigkc2NvcGUuYXNzb2NpYXRpb25zLmxlbmd0aD4wKSB7XG4gICAgICAgIGlmKCRzY29wZS5hc3NvY2lhdGlvbnNbMF1bJ1Rocm91Z2gnXSA9PT0gJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKCdUYWJsZS5UaHJvdWdoJywge2RiTmFtZSA6ICRzdGF0ZVBhcmFtcy5kYk5hbWUsIHRhYmxlTmFtZSA6ICRzdGF0ZVBhcmFtcy50YWJsZU5hbWV9KVxuICAgICAgICB9XG4gICAgfVxuXG5cbiAgICBmdW5jdGlvbiBmb3JlaWduQ29sdW1uT2JqKCkge1xuICAgICAgICB2YXIgZm9yZWlnbkNvbHMgPSB7fTtcbiAgICAgICAgJHNjb3BlLmFzc29jaWF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgaWYgKHJvdy5UYWJsZTEgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgcm93LlJlbGF0aW9uc2hpcDEgPT09ICdoYXNPbmUnKSB7XG4gICAgICAgICAgICAgICAgZm9yZWlnbkNvbHNbcm93LkFsaWFzMV0gPSByb3cuVGFibGUyXG4gICAgICAgICAgICB9IGVsc2UgaWYgKHJvdy5UYWJsZTIgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgcm93LlJlbGF0aW9uc2hpcDIgPT09ICdoYXNPbmUnKSB7XG4gICAgICAgICAgICAgICAgZm9yZWlnbkNvbHNbcm93LkFsaWFzMl0gPSByb3cuVGFibGUxXG4gICAgICAgICAgICB9XG4gICAgICAgIH0pXG4gICAgICAgICRzY29wZS5mb3JlaWduQ29scyA9IGZvcmVpZ25Db2xzO1xuICAgIH1cblxuICAgIGZvcmVpZ25Db2x1bW5PYmooKTtcblxuXG4gICAgJHNjb3BlLmN1cnJlbnRUYWJsZSA9ICRzdGF0ZVBhcmFtcztcblxuICAgICRzY29wZS5teUluZGV4ID0gMTtcblxuICAgICRzY29wZS5pZHMgPSAkc2NvcGUuc2luZ2xlVGFibGUubWFwKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICByZXR1cm4gcm93LmlkO1xuICAgIH0pXG5cbiAgICAvL2RlbGV0ZSBhIHJvdyBcbiAgICAkc2NvcGUuc2hvd0RlbGV0ZSA9IGZhbHNlO1xuICAgICRzY29wZS50b2dnbGVEZWxldGUgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgJHNjb3BlLnNob3dEZWxldGUgPSAhJHNjb3BlLnNob3dEZWxldGVcbiAgICB9XG5cbiAgICAkc2NvcGUuZGVsZXRlU2VsZWN0ZWQgPSBmdW5jdGlvbihkYiwgdGFibGUsIGluc3RhbmNlQXJyYXkpIHtcbiAgICAgICAgZm9yKHZhciBpID0gaW5zdGFuY2VBcnJheS5sZW5ndGgtMTsgaSA+PSAwOyBpLS0pe1xuICAgICAgICAgICAgdmFyIHJvdyA9IGluc3RhbmNlQXJyYXlbaV07XG4gICAgICAgICAgICB2YXIgbGVuZ3RoID0gaTtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKHJvdykgICAgICAgXG4gICAgICAgICAgICBpZiAocm93LnNlbGVjdGVkKSB7XG4gICAgICAgICAgICAgICAgVGFibGVGYWN0b3J5LnJlbW92ZVJvdyhkYiwgdGFibGUsIHJvd1sndmFsdWVzJ11bMF1bJ3ZhbHVlJ10sIGxlbmd0aClcbiAgICAgICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgJHNjb3BlLnNob3dEZWxldGUgPSBmYWxzZTtcbiAgICB9XG5cbiAgICAkc2NvcGUuc2VsZWN0QWxsID0gZnVuY3Rpb24oaW5zdGFuY2VBcnJheSkge1xuICAgICAgICBpZiAoJHNjb3BlLnNlbGVjdGVkQWxsKSB7XG4gICAgICAgICAgICBpbnN0YW5jZUFycmF5LmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICAgICAgcm93LnNlbGVjdGVkID0gdHJ1ZTtcbiAgICAgICAgICAgIH0pXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBpbnN0YW5jZUFycmF5LmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICAgICAgcm93LnNlbGVjdGVkID0gZmFsc2U7XG4gICAgICAgICAgICB9KVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLnVuY2hlY2tTZWxlY3RBbGwgPSBmdW5jdGlvbihpbnN0YW5jZUFycmF5KSB7XG4gICAgICAgIGlmICgkc2NvcGUuc2VsZWN0ZWRBbGwgPT09IHRydWUpIHtcbiAgICAgICAgICAgICRzY29wZS5zZWxlY3RlZEFsbCA9IGZhbHNlO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLnJlbW92ZVJvdyA9IGZ1bmN0aW9uKGRiLCB0YWJsZSwgcm93LCBpbnN0YW5jZUFycmF5KSB7XG4gICAgICAgIHZhciBsZW5ndGggPSBpbnN0YW5jZUFycmF5Lmxlbmd0aCAtIDE7XG4gICAgICAgIFRhYmxlRmFjdG9yeS5yZW1vdmVSb3coZGIsIHRhYmxlLCByb3csIGxlbmd0aClcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHJlc3VsdDtcbiAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICB9KVxuICAgIH1cblxuICAgICRzY29wZS5yZW1vdmVDb2x1bW4gPSBmdW5jdGlvbihkYiwgdGFibGUsIGNvbHVtbk5hbWUpIHtcbiAgICAgICAgVGFibGVGYWN0b3J5LnJlbW92ZUNvbHVtbihkYiwgdGFibGUsIGNvbHVtbk5hbWUpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgIENyZWF0ZUNvbHVtbnMoKTtcbiAgICAgICAgICAgIH0pXG4gICAgfVxuXG4gICAgJHNjb3BlLm5ld1JvdyA9IGZ1bmN0aW9uKGRiLCB0YWJsZSwgYXJyKSB7XG4gICAgICAgIHZhciBhbGxJZHMgPSBbXTtcbiAgICAgICAgYXJyLmZvckVhY2goZnVuY3Rpb24ocm93RGF0YSkge1xuICAgICAgICAgICAgYWxsSWRzLnB1c2gocm93RGF0YS52YWx1ZXNbMF0udmFsdWUpXG4gICAgICAgIH0pXG4gICAgICAgIHZhciBzb3J0ZWQgPSBhbGxJZHMuc29ydChmdW5jdGlvbihhLCBiKSB7XG4gICAgICAgICAgICByZXR1cm4gYiAtIGFcbiAgICAgICAgfSlcbiAgICAgICAgaWYgKHNvcnRlZC5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICBUYWJsZUZhY3RvcnkuYWRkUm93KGRiLCB0YWJsZSwgc29ydGVkWzBdICsgMSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbihyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0O1xuICAgICAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICAgICAgfSlcblxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgVGFibGVGYWN0b3J5LmFkZFJvdyhkYiwgdGFibGUsIDEpXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHJlc3VsdDtcbiAgICAgICAgICAgICAgICAgICAgQ3JlYXRlUm93cygpO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAkc2NvcGUuYWRkQ29sdW1uID0gZnVuY3Rpb24oZGIsIHRhYmxlKSB7XG4gICAgICAgIHZhciBjb2xOdW1zID0gJHNjb3BlLmNvbHVtbnMuam9pbignICcpLm1hdGNoKC9cXGQrL2cpO1xuICAgICAgICBpZiAoY29sTnVtcykge1xuICAgICAgICAgICAgdmFyIHNvcnRlZE51bXMgPSBjb2xOdW1zLnNvcnQoZnVuY3Rpb24oYSwgYikge1xuICAgICAgICAgICAgICAgIHJldHVybiBiIC0gYVxuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIHZhciBudW1Jbk5ldyA9IE51bWJlcihzb3J0ZWROdW1zWzBdKSArIDE7XG4gICAgICAgICAgICB2YXIgbmFtZU5ld0NvbCA9ICdDb2x1bW4gJyArIG51bUluTmV3LnRvU3RyaW5nKCk7XG5cbiAgICAgICAgICAgIFRhYmxlRmFjdG9yeS5hZGRDb2x1bW4oZGIsIHRhYmxlLCBuYW1lTmV3Q29sKVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldFNpbmdsZVRhYmxlKCRzdGF0ZVBhcmFtcy5kYk5hbWUsICRzdGF0ZVBhcmFtcy50YWJsZU5hbWUpXG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbih0aGVUYWJsZSkge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSB0aGVUYWJsZVswXTtcbiAgICAgICAgICAgICAgICAgICAgQ3JlYXRlQ29sdW1ucygpO1xuICAgICAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHZhciBuZXh0Q29sTnVtID0gJHNjb3BlLmNvbHVtbnMubGVuZ3RoICsgMTtcbiAgICAgICAgICAgIHZhciBuZXdDb2xOYW1lID0gJ0NvbHVtbiAnICsgbmV4dENvbE51bTtcbiAgICAgICAgICAgIFRhYmxlRmFjdG9yeS5hZGRDb2x1bW4oZGIsIHRhYmxlLCAnQ29sdW1uIDEnKVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldFNpbmdsZVRhYmxlKCRzdGF0ZVBhcmFtcy5kYk5hbWUsICRzdGF0ZVBhcmFtcy50YWJsZU5hbWUpXG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbih0aGVUYWJsZSkge1xuICAgICAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSB0aGVUYWJsZVswXTtcbiAgICAgICAgICAgICAgICAgICAgQ3JlYXRlQ29sdW1ucygpO1xuICAgICAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgfVxuXG4gICAgfVxuXG4gICAgLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL09yZ2FuaXppbmcgc3R1ZmYgaW50byBhcnJheXMvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG5cbiAgICAvLyBHZXQgYWxsIG9mIHRoZSBjb2x1bW5zIHRvIGNyZWF0ZSB0aGUgY29sdW1ucyBvbiB0aGUgYm9vdHN0cmFwIHRhYmxlXG5cbiAgICBmdW5jdGlvbiBDcmVhdGVDb2x1bW5zKCkge1xuICAgICAgICAkc2NvcGUuY29sdW1ucyA9IFtdO1xuICAgICAgICAkc2NvcGUub3JpZ2luYWxDb2xWYWxzID0gW107XG4gICAgICAgIHZhciB0YWJsZSA9ICRzY29wZS5zaW5nbGVUYWJsZVswXTtcblxuXG4gICAgICAgIGZvciAodmFyIHByb3AgaW4gdGFibGUpIHtcbiAgICAgICAgICAgIGlmIChwcm9wICE9PSAnY3JlYXRlZF9hdCcgJiYgcHJvcCAhPT0gJ3VwZGF0ZWRfYXQnKSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLmNvbHVtbnMucHVzaChwcm9wKTtcbiAgICAgICAgICAgICAgICAkc2NvcGUub3JpZ2luYWxDb2xWYWxzLnB1c2gocHJvcCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBDcmVhdGVDb2x1bW5zKCk7XG5cbiAgICBmdW5jdGlvbiBjcmVhdGVWaXJ0dWFsQ29sdW1ucygpIHtcbiAgICAgICAgaWYgKCRzY29wZS5hc3NvY2lhdGlvbnMubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgJHNjb3BlLnZpcnR1YWxDb2x1bW5zID0gW107XG4gICAgICAgICAgICAkc2NvcGUuYXNzb2NpYXRpb25zLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICAgICAgaWYgKHJvdy5UYWJsZTEgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgcm93LlJlbGF0aW9uc2hpcDEgPT09ICdoYXNNYW55Jykge1xuICAgICAgICAgICAgICAgICAgICB2YXIgdmlydHVhbCA9IHt9O1xuICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLm5hbWUgPSByb3cuQWxpYXMxO1xuICAgICAgICAgICAgICAgICAgICBpZiAocm93LlRocm91Z2gpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwudGFibGUgPSByb3cuVGhyb3VnaDtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwuY29sdW1ua2V5ID0gcm93LkFsaWFzMTtcbiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZpcnR1YWwudGFibGUgPSByb3cuVGFibGUyO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5jb2x1bW5rZXkgPSByb3cuQWxpYXMyO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS52aXJ0dWFsQ29sdW1ucy5wdXNoKHZpcnR1YWwpO1xuICAgICAgICAgICAgICAgIH0gZWxzZSBpZiAocm93LlRhYmxlMiA9PT0gJHNjb3BlLnRoZVRhYmxlTmFtZSAmJiByb3cuUmVsYXRpb25zaGlwMiA9PT0gJ2hhc01hbnknKSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciB2aXJ0dWFsID0ge307XG4gICAgICAgICAgICAgICAgICAgIHZpcnR1YWwubmFtZSA9IHJvdy5BbGlhczI7XG4gICAgICAgICAgICAgICAgICAgIGlmIChyb3cuVGhyb3VnaCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC50YWJsZSA9IHJvdy5UaHJvdWdoO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC5jb2x1bW5rZXkgPSByb3cuQWxpYXMyO1xuICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmlydHVhbC50YWJsZSA9IHJvdy5UYWJsZTE7XG4gICAgICAgICAgICAgICAgICAgICAgICB2aXJ0dWFsLmNvbHVtbmtleSA9IHJvdy5BbGlhczE7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLnZpcnR1YWxDb2x1bW5zLnB1c2godmlydHVhbCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSlcbiAgICAgICAgfVxuICAgIH1cblxuICAgIGNyZWF0ZVZpcnR1YWxDb2x1bW5zKCk7XG5cbiAgICAvL3RoaXMgZnVuY3Rpb24gd2lsbCByZSBydW4gd2hlbiB0aGUgZmlsdGVyIGZ1bmN0aW9uIGlzIGludm9rZWQsIGluIG9yZGVyIHRvIHJlcG9wdWxhdGUgdGhlIHRhYmxlXG4gICAgZnVuY3Rpb24gQ3JlYXRlUm93cygpIHtcbiAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkgPSBbXTtcbiAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICB2YXIgcm93VmFsdWVzID0gW107XG4gICAgICAgICAgICB2YXIgcm93T2JqID0ge307XG5cbiAgICAgICAgICAgIGZvciAodmFyIHByb3AgaW4gcm93KSB7XG4gICAgICAgICAgICAgICAgaWYgKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpIHJvd1ZhbHVlcy5wdXNoKHtcbiAgICAgICAgICAgICAgICAgICAgY29sOiBwcm9wLFxuICAgICAgICAgICAgICAgICAgICB2YWx1ZTogcm93W3Byb3BdXG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJvd09iai52YWx1ZXMgPSByb3dWYWx1ZXM7XG4gICAgICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheS5wdXNoKHJvd09iaik7XG4gICAgICAgIH0pXG4gICAgfVxuXG4gICAgLy8gU29ydCB0aGUgdmFsdWVzIGluIHNpbmdsZVRhYmxlIHNvIHRoYXQgYWxsIHRoZSB2YWx1ZXMgZm9yIGEgZ2l2ZW4gcm93IGFyZSBncm91cGVkXG4gICAgQ3JlYXRlUm93cygpO1xuICAgIC8vc2VuZHMgdGhlIGZpbHRlcmluZyBxdWVyeSBhbmQgdGhlbiByZSByZW5kZXJzIHRoZSB0YWJsZSB3aXRoIGZpbHRlcmVkIGRhdGFcbiAgICAkc2NvcGUuZmlsdGVyID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIGRhdGEpIHtcbiAgICAgICAgVGFibGVGYWN0b3J5LmZpbHRlcihkYk5hbWUsIHRhYmxlTmFtZSwgZGF0YSlcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHJlc3VsdC5kYXRhO1xuICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgIH0pXG4gICAgfVxuXG5cbiAgICAkc2NvcGUuY2hlY2tGb3JlaWduID0gZnVuY3Rpb24oY29sKSB7XG4gICAgICAgIHJldHVybiAkc2NvcGUuZm9yZWlnbkNvbHMuaGFzT3duUHJvcGVydHkoY29sKTtcbiAgICB9XG5cbiAgICAkc2NvcGUuZmluZFByaW1hcnkgPSBUYWJsZUZhY3RvcnkuZmluZFByaW1hcnk7XG5cbiAgICAvLyoqKioqKioqKioqKiBJbXBvcnRhbnQgKioqKioqKioqXG4gICAgLy8gTWFrZSBzdXJlIHRvIHVwZGF0ZSB0aGUgcm93IHZhbHVlcyBCRUZPUkUgdGhlIGNvbHVtbiBuYW1lXG4gICAgLy8gVGhlIHJvd1ZhbHNUb1VwZGF0ZSBhcnJheSBzdG9yZXMgdGhlIHZhbHVlcyBvZiB0aGUgT1JJR0lOQUwgY29sdW1uIG5hbWVzIHNvIGlmIHRoZSBjb2x1bW4gbmFtZSBpcyB1cGRhdGVkIGFmdGVyIHRoZSByb3cgdmFsdWUsIHdlIHN0aWxsIGhhdmUgcmVmZXJlbmNlIHRvIHdoaWNoIGNvbHVtbiB0aGUgcm93IHZhbHVlIHJlZmVyZW5jZXNcblxuXG4gICAgLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1VwZGF0aW5nIENvbHVtbiBTdHVmZi8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgICRzY29wZS5jb2xWYWxzVG9VcGRhdGUgPSBbXTtcblxuICAgICRzY29wZS51cGRhdGVDb2x1bW5zID0gZnVuY3Rpb24ob2xkLCBuZXdDb2xOYW1lLCBpKSB7XG4gICAgICAgICRzY29wZS5jb2x1bW5zW2ldID0gbmV3Q29sTmFtZTtcblxuICAgICAgICB2YXIgY29sT2JqID0geyBvbGRWYWw6ICRzY29wZS5vcmlnaW5hbENvbFZhbHNbaV0sIG5ld1ZhbDogbmV3Q29sTmFtZSB9O1xuXG4gICAgICAgIC8vIGlmIHRoZXJlIGlzIG5vdGhpbmcgaW4gdGhlIGFycmF5IHRvIHVwZGF0ZSwgcHVzaCB0aGUgdXBkYXRlIGludG8gaXRcbiAgICAgICAgaWYgKCRzY29wZS5jb2xWYWxzVG9VcGRhdGUubGVuZ3RoID09PSAwKSB7ICRzY29wZS5jb2xWYWxzVG9VcGRhdGUucHVzaChjb2xPYmopOyB9IGVsc2Uge1xuICAgICAgICAgICAgZm9yICh2YXIgZSA9IDA7IGUgPCAkc2NvcGUuY29sVmFsc1RvVXBkYXRlLmxlbmd0aDsgZSsrKSB7XG4gICAgICAgICAgICAgICAgaWYgKCRzY29wZS5jb2xWYWxzVG9VcGRhdGVbZV0ub2xkVmFsID09PSBjb2xPYmoub2xkVmFsKSB7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5jb2xWYWxzVG9VcGRhdGVbZV0gPSBjb2xPYmo7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAkc2NvcGUuY29sVmFsc1RvVXBkYXRlLnB1c2goY29sT2JqKTtcbiAgICAgICAgfVxuICAgICAgICAvLyBjaGVjayB0byBzZWUgaWYgdGhlIHJvdyBpcyBhbHJlYWR5IHNjaGVkdWxlZCB0byBiZSB1cGRhdGVkLCBpZiBpdCBpcywgdGhlbiB1cGRhdGUgaXQgd2l0aCB0aGUgbmV3IHRoaW5nIHRvIGJlIHVwZGF0ZWRcbiAgICB9XG5cbiAgICAvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vVXBkYXRpbmcgUm93IFN0dWZmLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuXG4gICAgJHNjb3BlLnJvd1ZhbHNUb1VwZGF0ZSA9IFtdO1xuXG4gICAgJHNjb3BlLnVwZGF0ZVJvdyA9IGZ1bmN0aW9uKG9sZCwgbmV3Q2VsbCwgcm93LCBpLCBqKXtcbiAgICAgICAgdmFyIGNvbHMgPSAkc2NvcGUub3JpZ2luYWxDb2xWYWxzO1xuICAgICAgICB2YXIgZm91bmQgPSBmYWxzZTtcbiAgICAgICAgdmFyIGNvbE5hbWUgPSBjb2xzW2pdO1xuICAgICAgICBmb3IodmFyIGsgPSAwOyBrIDwgJHNjb3BlLnJvd1ZhbHNUb1VwZGF0ZS5sZW5ndGg7IGsrKyl7XG4gICAgICAgICAgICB2YXIgb2JqID0gJHNjb3BlLnJvd1ZhbHNUb1VwZGF0ZVtrXTtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKG9iailcbiAgICAgICAgICAgIGlmKG9ialsnaWQnXSA9PT0gaSl7XG4gICAgICAgICAgICAgICAgZm91bmQgPSB0cnVlO1xuICAgICAgICAgICAgICAgIGlmKG9ialtjb2xOYW1lXSkgb2JqW2NvbE5hbWVdID0gbmV3Q2VsbDtcbiAgICAgICAgICAgICAgICBvYmpbY29sTmFtZV0gPSBuZXdDZWxsO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGlmKCFmb3VuZCkge1xuICAgICAgICAgICAgdmFyIHJvd09iaiA9IHt9O1xuICAgICAgICAgICAgcm93T2JqWydpZCddID0gaTtcbiAgICAgICAgICAgIHJvd09ialtjb2xOYW1lXSA9IG5ld0NlbGw7XG4gICAgICAgICAgICAkc2NvcGUucm93VmFsc1RvVXBkYXRlLnB1c2gocm93T2JqKVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgJHNjb3BlLnVwZGF0ZUJhY2tlbmQgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIGRhdGEgPSB7IHJvd3M6ICRzY29wZS5yb3dWYWxzVG9VcGRhdGUsIGNvbHVtbnM6ICRzY29wZS5jb2xWYWxzVG9VcGRhdGUgfVxuICAgICAgICBUYWJsZUZhY3RvcnkudXBkYXRlQmFja2VuZCgkc2NvcGUudGhlRGJOYW1lLCAkc2NvcGUudGhlVGFibGVOYW1lLCBkYXRhKTtcbiAgICB9XG5cblxuICAgICRzY29wZS5kZWxldGVUYWJsZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgICBUYWJsZUZhY3RvcnkuZGVsZXRlVGFibGUoJHNjb3BlLmN1cnJlbnRUYWJsZSlcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnVGFibGUnLCB7IGRiTmFtZTogJHNjb3BlLnRoZURiTmFtZSB9LCB7IHJlbG9hZDogdHJ1ZSB9KVxuICAgICAgICAgICAgfSlcbiAgICB9XG5cbiAgICAvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vUXVlcnlpbmcgU3R1ZmYvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG5cbiAgICAkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zID0gW107XG5cbiAgICAkc2NvcGUudGFibGVzVG9RdWVyeSA9IFtdO1xuXG4gICAgYXNzb2NpYXRpb25zLmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgIGlmIChyb3cuVGFibGUxID09PSAkc2NvcGUudGhlVGFibGVOYW1lICYmICRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnMuaW5kZXhPZihyb3cuVGFibGUyKSA9PSAtMSkge1xuICAgICAgICAgICAgJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9ucy5wdXNoKHJvdy5UYWJsZTIpO1xuICAgICAgICB9IGVsc2UgaWYgKHJvdy5UYWJsZTIgPT09ICRzY29wZS50aGVUYWJsZU5hbWUgJiYgJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9ucy5pbmRleE9mKHJvdy5UYWJsZTEpID09IC0xKSB7XG4gICAgICAgICAgICAkc2NvcGUuY3VycmVudFRhYmxlQXNzb2NpYXRpb25zLnB1c2gocm93LlRhYmxlMSk7XG4gICAgICAgIH1cbiAgICB9KVxuXG4gICAgJHNjb3BlLmdldEFzc29jaWF0ZWQgPSBmdW5jdGlvbih2YWwpIHtcbiAgICAgICAgaWYgKCRzY29wZS50YWJsZXNUb1F1ZXJ5LmluZGV4T2YoJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9uc1t2YWxdKSA9PT0gLTEpIHtcbiAgICAgICAgICAgICRzY29wZS50YWJsZXNUb1F1ZXJ5LnB1c2goJHNjb3BlLmN1cnJlbnRUYWJsZUFzc29jaWF0aW9uc1t2YWxdKVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdmFyIGkgPSAkc2NvcGUudGFibGVzVG9RdWVyeS5pbmRleE9mKCRzY29wZS5jdXJyZW50VGFibGVBc3NvY2lhdGlvbnNbdmFsXSk7XG4gICAgICAgICAgICAkc2NvcGUudGFibGVzVG9RdWVyeS5zcGxpY2UoaSwgMSlcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS5jb2x1bW5zRm9yUXVlcnkgPSBbXTtcblxuICAgICRzY29wZS5nZXRDb2x1bW5zRm9yVGFibGUgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIHByb21pc2VzRm9yQ29sdW1ucyA9IFtdO1xuICAgICAgICAkc2NvcGUudGFibGVzVG9RdWVyeS5mb3JFYWNoKGZ1bmN0aW9uKHRhYmxlTmFtZSkge1xuICAgICAgICAgICAgcmV0dXJuIHByb21pc2VzRm9yQ29sdW1ucy5wdXNoKFRhYmxlRmFjdG9yeS5nZXRDb2x1bW5zRm9yVGFibGUoJHNjb3BlLnRoZURiTmFtZSwgdGFibGVOYW1lKSlcbiAgICAgICAgfSlcbiAgICAgICAgUHJvbWlzZS5hbGwocHJvbWlzZXNGb3JDb2x1bW5zKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oY29sdW1ucykge1xuICAgICAgICAgICAgICAgIGNvbHVtbnMuZm9yRWFjaChmdW5jdGlvbihjb2x1bW4pIHtcbiAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmNvbHVtbnNGb3JRdWVyeS5wdXNoKGNvbHVtbik7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS4kZXZhbEFzeW5jKClcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgfSlcblxuICAgIH1cblxuICAgIHZhciBzZWxlY3RlZENvbHVtbnMgPSB7fTtcbiAgICB2YXIgcXVlcnlUYWJsZTtcblxuICAgICRzY29wZS5nZXREYXRhRnJvbUNvbHVtbnMgPSBmdW5jdGlvbih2YWwpIHtcbiAgICAgICAgaWYoIXNlbGVjdGVkQ29sdW1ucykgc2VsZWN0ZWRDb2x1bW5zID0gW107XG5cbiAgICAgICAgdmFyIGNvbHVtbk5hbWUgPSAkc2NvcGUuY29sdW1uc0ZvclF1ZXJ5WzBdWydjb2x1bW5zJ11bdmFsLmldO1xuICAgICAgICB2YXIgdGFibGVOYW1lID0gdmFsLnRhYmxlTmFtZVxuICAgICAgICBxdWVyeVRhYmxlID0gdGFibGVOYW1lO1xuXG4gICAgICAgIGlmICghc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0pIHNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdID0gW107XG4gICAgICAgIGlmIChzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXS5pbmRleE9mKGNvbHVtbk5hbWUpICE9PSAtMSkge1xuICAgICAgICAgICAgc2VsZWN0ZWRDb2x1bW5zW3RhYmxlTmFtZV0uc3BsaWNlKHNlbGVjdGVkQ29sdW1uc1t0YWJsZU5hbWVdLmluZGV4T2YoY29sdW1uTmFtZSksIDEpXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBzZWxlY3RlZENvbHVtbnNbdGFibGVOYW1lXS5wdXNoKGNvbHVtbk5hbWUpO1xuICAgICAgICB9XG4gICAgICAgICRzY29wZS5zZWxlY3RlZENvbHVtbnMgPSBzZWxlY3RlZENvbHVtbnM7XG4gICAgfVxuXG5cbiAgICAvLyBSdW5uaW5nIHRoZSBxdWVyeSArIHJlbmRlcmluZyB0aGUgcXVlcnlcbiAgICAkc2NvcGUucmVzdWx0T2ZRdWVyeSA9IFtdO1xuXG4gICAgJHNjb3BlLnF1ZXJ5UmVzdWx0O1xuXG4gICAgJHNjb3BlLmFyciA9IFtdO1xuXG5cbiAgICAvLyB0aGVUYWJsZU5hbWVcblxuICAgICRzY29wZS5ydW5Kb2luID0gZnVuY3Rpb24oKSB7XG4gICAgICAgIC8vIGRiTmFtZSwgdGFibGUxLCBhcnJheU9mVGFibGVzLCBzZWxlY3RlZENvbHVtbnMsIGFzc29jaWF0aW9uc1xuICAgICAgICB2YXIgY29sdW1uc1RvUmV0dXJuID0gJHNjb3BlLmNvbHVtbnMubWFwKGZ1bmN0aW9uKGNvbE5hbWUpe1xuICAgICAgICAgICAgcmV0dXJuICRzY29wZS50aGVUYWJsZU5hbWUgKyAnLicgKyBjb2xOYW1lO1xuICAgICAgICB9KVxuICAgICAgICBmb3IodmFyIHByb3AgaW4gJHNjb3BlLnNlbGVjdGVkQ29sdW1ucyl7XG4gICAgICAgICAgICRzY29wZS5zZWxlY3RlZENvbHVtbnNbcHJvcF0uZm9yRWFjaChmdW5jdGlvbihjb2wpe1xuICAgICAgICAgICAgICAgIGNvbHVtbnNUb1JldHVybi5wdXNoKHByb3AgKyAnLicgKyBjb2wpXG4gICAgICAgICAgIH0pXG4gICAgICAgIH1cbiAgICAgICAgVGFibGVGYWN0b3J5LnJ1bkpvaW4oJHNjb3BlLnRoZURiTmFtZSwgJHNjb3BlLnRoZVRhYmxlTmFtZSwgJHNjb3BlLnRhYmxlc1RvUXVlcnksICRzY29wZS5zZWxlY3RlZENvbHVtbnMsICRzY29wZS5hc3NvY2lhdGlvbnMsIGNvbHVtbnNUb1JldHVybilcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHF1ZXJ5UmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5sb2coJ1FVRVJZUlJFU1VMVCcsIHF1ZXJ5UmVzdWx0KTtcbiAgICAgICAgICAgICAgICAkc2NvcGUucXVlcnlSZXN1bHQgPSBxdWVyeVJlc3VsdDtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAkc3RhdGUuZ28oJ1RhYmxlLlNpbmdsZS5xdWVyeScpO1xuICAgICAgICAgICAgfSlcbiAgICB9XG5cbiAgICAkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQgPSB0cnVlO1xuXG4gICAgJHNjb3BlLm9wZW4gPSBmdW5jdGlvbiAoZGJOYW1lLCB0YmxOYW1lLCBjb2wsIGluZGV4KSB7XG5cbiAgICAgIHZhciBtb2RhbEluc3RhbmNlID0gJHVpYk1vZGFsLm9wZW4oe1xuICAgICAgICBhbmltYXRpb246ICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCxcbiAgICAgICAgYmFja2Ryb3A6IGZhbHNlLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL2Fzc29jaWF0aW9uLm1vZGFsLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnQXNzb2NpYXRpb25JbnN0YW5jZUN0cmwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgZm9yZWlnbkNvbHM6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiAkc2NvcGUuZm9yZWlnbkNvbHM7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBmb3JUYWJsZTogZnVuY3Rpb24oVGFibGVGYWN0b3J5KXtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKHRibE5hbWUpXG4gICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmZpbmRQcmltYXJ5KGRiTmFtZSwgdGJsTmFtZSk7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBmb3JUYWJsZU5hbWU6IGZ1bmN0aW9uKCl7XG4gICAgICAgICAgICByZXR1cm4gdGJsTmFtZTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIGN1cnJUYWJsZTogZnVuY3Rpb24oKXtcbiAgICAgICAgICAgIHJldHVybiAkc2NvcGUudGhlVGFibGVOYW1lXG4gICAgICAgICAgfSxcbiAgICAgICAgICBjb2xOYW1lOiBmdW5jdGlvbiAoKXtcbiAgICAgICAgICAgIHJldHVybiBjb2w7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBpZDE6IGZ1bmN0aW9uKCl7XG4gICAgICAgICAgICByZXR1cm4gaW5kZXg7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9KTtcblxuICAgICAgbW9kYWxJbnN0YW5jZS5yZXN1bHQudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKFwiQ0xPU0VEXCIpXG4gICAgICAgICRzY29wZS4kZXZhbEFzeW5jKCk7XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgJHNjb3BlLnRvZ2dsZUFuaW1hdGlvbiA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICRzY29wZS5hbmltYXRpb25zRW5hYmxlZCA9ICEkc2NvcGUuYW5pbWF0aW9uc0VuYWJsZWQ7XG4gICAgfTtcblxuICAgICRzY29wZS5maWx0ZXJlZFJvd3M9W107XG4gICAgJHNjb3BlLmN1cnJlbnRQYWdlPTE7XG4gICAgJHNjb3BlLm51bVBlclBhZ2U9MTA7XG4gICAgJHNjb3BlLm1heFNpemU9NTtcblxuICAgICRzY29wZS4kd2F0Y2goXCJjdXJyZW50UGFnZSArIG51bVBlclBhZ2VcIiwgZnVuY3Rpb24oKXtcbiAgICAgICAgdmFyIGJlZ2luID0gKCgkc2NvcGUuY3VycmVudFBhZ2UgLSAxKSAqICRzY29wZS5udW1QZXJQYWdlKTtcbiAgICAgICAgdmFyIGVuZCA9IGJlZ2luICsgJHNjb3BlLm51bVBlclBhZ2U7XG4gICAgICAgICRzY29wZS5maWx0ZXJlZFJvd3MgPSAkc2NvcGUuaW5zdGFuY2VBcnJheS5zbGljZShiZWdpbiwgZW5kKTtcbiAgICB9KVxuXG4gICAgJHNjb3BlLiR3YXRjaChcImluc3RhbmNlQXJyYXlcIiwgZnVuY3Rpb24oKXtcbiAgICAgICAgdmFyIGJlZ2luID0gKCgkc2NvcGUuY3VycmVudFBhZ2UgLSAxKSAqICRzY29wZS5udW1QZXJQYWdlKTtcbiAgICAgICAgdmFyIGVuZCA9IGJlZ2luICsgJHNjb3BlLm51bVBlclBhZ2U7XG4gICAgICAgICRzY29wZS5maWx0ZXJlZFJvd3MgPSAkc2NvcGUuaW5zdGFuY2VBcnJheS5zbGljZShiZWdpbiwgZW5kKTtcbiAgICB9KVxuXG4gICAgJHNjb3BlLmNzdiA9IGZ1bmN0aW9uKHRhYmxlKXtcbiAgICAgICAgYWxhc3FsKFwiU0VMRUNUICogSU5UTyBDU1YoJ215ZGF0YS5jc3YnLCB7aGVhZGVyczp0cnVlfSkgRlJPTSA/XCIsW3RhYmxlXSk7XG4gICAgfSAgICBcblxufSk7XG4iLCJhcHAuY29udHJvbGxlcignVGFibGVDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgYWxsVGFibGVzLCAkc3RhdGUsIFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zLCAkdWliTW9kYWwsIEhvbWVGYWN0b3J5LCBhc3NvY2lhdGlvbnMsIGFsbENvbHVtbnMpIHtcblxuXHQkc2NvcGUuYWxsVGFibGVzID0gYWxsVGFibGVzO1xuXG5cdCRzY29wZS5jb2x1bW5BcnJheSA9IFtdO1xuXG5cdCRzY29wZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lXG5cblx0JHNjb3BlLmFzc29jaWF0aW9ucyA9IGFzc29jaWF0aW9ucztcblxuXHQkc2NvcGUuYWxsQ29sdW1ucyA9IGFsbENvbHVtbnM7XG5cblx0JHNjb3BlLmFzc29jaWF0aW9uVGFibGUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lICsgJ19hc3NvYyc7XG5cblx0JHNjb3BlLm51bVRhYmxlcyA9ICRzY29wZS5hbGxUYWJsZXMucm93cy5sZW5ndGg7XG5cblx0JHNjb3BlLmFkZCA9IGZ1bmN0aW9uKCkge1xuXHRcdCRzY29wZS5jb2x1bW5BcnJheS5wdXNoKCcxJyk7XG5cdH1cblxuXHQkc2NvcGUuJHN0YXRlID0gJHN0YXRlOyBcdC8vIHVzZWQgdG8gaGlkZSB0aGUgbGlzdCBvZiBhbGwgdGFibGVzIHdoZW4gaW4gc2luZ2xlIHRhYmxlIHN0YXRlXG5cblx0JHNjb3BlLmFzc29jaWF0aW9uVHlwZXMgPSBbJ2hhc09uZScsICdoYXNNYW55J107XG5cblx0JHNjb3BlLmRiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG5cblx0JHNjb3BlLnN1Ym1pdHRlZCA9IGZhbHNlO1xuXG5cdCRzY29wZS5tYWtlQXNzb2NpYXRpb25zID0gZnVuY3Rpb24oYXNzb2NpYXRpb24sIGRiTmFtZSkge1xuXHRcdCRzY29wZS5zdWJtaXR0ZWQgPSB0cnVlO1xuXHRcdFRhYmxlRmFjdG9yeS5tYWtlQXNzb2NpYXRpb25zKGFzc29jaWF0aW9uLCBkYk5hbWUpXG5cdH0gXG5cblx0JHNjb3BlLndoZXJlYmV0d2VlbiA9IGZ1bmN0aW9uKGNvbmRpdGlvbikge1xuXHRcdGlmKGNvbmRpdGlvbiA9PT0gXCJXSEVSRSBCRVRXRUVOXCIgfHwgY29uZGl0aW9uID09PSBcIldIRVJFIE5PVCBCRVRXRUVOXCIpIHJldHVybiB0cnVlO1xuXHR9XG5cblx0JHNjb3BlLmNyZWF0ZVRhYmxlID0gZnVuY3Rpb24odGFibGUpe1xuXHRcdFRhYmxlRmFjdG9yeS5jcmVhdGVUYWJsZSh0YWJsZSlcblx0XHQudGhlbihmdW5jdGlvbigpe1xuXHRcdFx0JHN0YXRlLmdvKCdUYWJsZScsIHtkYk5hbWU6ICRzY29wZS5kYk5hbWV9LCB7cmVsb2FkOiB0cnVlfSk7XG5cdFx0fSlcblx0fVxuXG5cdCRzY29wZS5jb2x1bW5EYXRhVHlwZSA9IGZ1bmN0aW9uKCkge1xuXHRcdCRzY29wZS5hbGxDb2x1bW5zLmZvckVhY2goZnVuY3Rpb24ob2JqKSB7XG5cdFx0XHRpZihvYmoudGFibGVfbmFtZSA9PT0gJHNjb3BlLnF1ZXJ5LnRhYmxlMSAmJiBvYmouY29sdW1uX25hbWUgPT09ICRzY29wZS5xdWVyeS5jb2x1bW4pICRzY29wZS50eXBlID0gb2JqLmRhdGFfdHlwZTtcblx0XHR9KVxuXHR9XG5cblx0JHNjb3BlLnNlbGVjdGVkQXNzb2MgPSB7fTtcblxuXHQkc2NvcGUuc3VibWl0UXVlcnkgPSBUYWJsZUZhY3Rvcnkuc3VibWl0UXVlcnk7XG5cblx0JHNjb3BlLmFzc29jdGFibGUgPSBmdW5jdGlvbiAodGFibGVOYW1lKXtcblx0XHRyZXR1cm4gdGFibGVOYW1lID09PSAkc3RhdGVQYXJhbXMuZGJOYW1lK1wiX2Fzc29jXCI7XG5cdH1cblxufSk7XG4iLCJhcHAuZmFjdG9yeSgnVGFibGVGYWN0b3J5JywgZnVuY3Rpb24gKCRodHRwLCAkc3RhdGVQYXJhbXMpIHtcblxuXHR2YXIgVGFibGVGYWN0b3J5ID0ge307XG5cblx0ZnVuY3Rpb24gcmVzVG9EYXRhKHJlcykge1xuICAgICAgICByZXR1cm4gcmVzLmRhdGE7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldEFsbFRhYmxlcyA9IGZ1bmN0aW9uKGRiTmFtZSl7XG4gICAgXHRyZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUpXG4gICAgXHQudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmdldFNpbmdsZVRhYmxlID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZ2V0RGJOYW1lID0gZnVuY3Rpb24oZGJOYW1lKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9tYXN0ZXJkYi8nICsgZGJOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmZpbHRlciA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCBkYXRhKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5wdXQoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSArICcvZmlsdGVyJywgZGF0YSlcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkudXBkYXRlQmFja2VuZCA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCBkYXRhKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5wdXQoJ2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lLCBkYXRhKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5hZGRSb3cgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgcm93TnVtYmVyKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCdhcGkvY2xpZW50ZGIvYWRkcm93LycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUsIHtyb3dOdW1iZXI6IHJvd051bWJlcn0pXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LnJlbW92ZVJvdyA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lLCByb3dJZCwgbGVuZ3RoKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmRlbGV0ZSgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lICsgJy8nICsgcm93SWQgKyAnLycgKyBsZW5ndGgpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSlcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkucmVtb3ZlQ29sdW1uID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIGNvbHVtbk5hbWUpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL2NsaWVudGRiLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUgKyAnL2NvbHVtbi8nICsgY29sdW1uTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKVxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5hZGRDb2x1bW4gPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgbnVtTmV3Q29sKXtcbiAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJ2FwaS9jbGllbnRkYi9hZGRjb2x1bW4vJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSArICcvJyArIG51bU5ld0NvbClcbiAgICB9XG4gICAgVGFibGVGYWN0b3J5LmNyZWF0ZVRhYmxlID0gZnVuY3Rpb24odGFibGUpe1xuICAgICAgICB0YWJsZS5kYk5hbWUgPSAkc3RhdGVQYXJhbXMuZGJOYW1lO1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL2FwaS9jbGllbnRkYicsIHRhYmxlKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5kZWxldGVUYWJsZSA9IGZ1bmN0aW9uKGN1cnJlbnRUYWJsZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL2NsaWVudGRiLycgKyBjdXJyZW50VGFibGUuZGJOYW1lICsgJy8nICsgY3VycmVudFRhYmxlLnRhYmxlTmFtZSlcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkubWFrZUFzc29jaWF0aW9ucyA9IGZ1bmN0aW9uKGFzc29jaWF0aW9uLCBkYk5hbWUpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9hcGkvY2xpZW50ZGIvJyArIGRiTmFtZSArICcvYXNzb2NpYXRpb24nLCBhc3NvY2lhdGlvbilcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZGVsZXRlRGIgPSBmdW5jdGlvbihkYk5hbWUpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmRlbGV0ZSgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRBc3NvY2lhdGlvbnMgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2NsaWVudGRiL2Fzc29jaWF0aW9udGFibGUvJyArIGRiTmFtZSArICcvJyArIHRhYmxlTmFtZSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICAgVGFibGVGYWN0b3J5LmdldEFsbEFzc29jaWF0aW9ucyA9IGZ1bmN0aW9uKGRiTmFtZSkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2NsaWVudGRiL2FsbGFzc29jaWF0aW9ucy8nICsgZGJOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRBbGxDb2x1bW5zID0gZnVuY3Rpb24oZGJOYW1lKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvZ2V0YWxsY29sdW1ucy8nICsgZGJOYW1lKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRDb2x1bW5zRm9yVGFibGUgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvY2xpZW50ZGIvY29sdW1uc2ZvcnRhYmxlLycgKyBkYk5hbWUgKyAnLycgKyB0YWJsZU5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LnJ1bkpvaW4gPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlMSwgYXJyYXlPZlRhYmxlcywgc2VsZWN0ZWRDb2x1bW5zLCBhc3NvY2lhdGlvbnMsIGNvbHNUb1JldHVybikge1xuICAgICAgICB2YXIgZGF0YSA9IHt9O1xuICAgICAgICBkYXRhLmRiTmFtZSA9IGRiTmFtZTtcbiAgICAgICAgZGF0YS50YWJsZTIgPSBhcnJheU9mVGFibGVzWzBdO1xuICAgICAgICBkYXRhLmFycmF5T2ZUYWJsZXMgPSBhcnJheU9mVGFibGVzO1xuICAgICAgICBkYXRhLnNlbGVjdGVkQ29sdW1ucyA9IHNlbGVjdGVkQ29sdW1ucztcbiAgICAgICAgZGF0YS5jb2xzVG9SZXR1cm4gPSBjb2xzVG9SZXR1cm47XG5cbiAgICAgICAgLy8gW2hhc01hbnksIGhhc09uZSwgaGFzTWFueSBwcmltYXJ5IGtleSwgaGFzT25lIGZvcmdlaW4ga2V5XVxuXG4gICAgICAgIGFzc29jaWF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgaWYocm93LlRhYmxlMSA9PT0gdGFibGUxICYmIHJvdy5UYWJsZTIgPT09IGRhdGEudGFibGUyKXtcbiAgICAgICAgICAgICAgICBkYXRhLmFsaWFzID0gcm93LkFsaWFzMTtcbiAgICAgICAgICAgICAgICBpZihyb3cuUmVsYXRpb25zaGlwMSA9PT0gJ2hhc09uZScpe1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMSA9IHJvdy5UYWJsZTI7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUyID0gcm93LlRhYmxlMTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZXtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTEgPSByb3cuVGFibGUxO1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMiA9IHJvdy5UYWJsZTI7ICAgXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSBpZihyb3cuVGFibGUxID09PSBkYXRhLnRhYmxlMiAmJiByb3cuVGFibGUyID09PSB0YWJsZTEpe1xuICAgICAgICAgICAgICAgIGRhdGEuYWxpYXMgPSByb3cuQWxpYXMxO1xuICAgICAgICAgICAgICAgIGlmKHJvdy5SZWxhdGlvbnNoaXAxID09PSAnaGFzTWFueScpe1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMSA9IHJvdy5UYWJsZTE7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudGFibGUyID0gcm93LlRhYmxlMjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZXtcbiAgICAgICAgICAgICAgICAgICAgZGF0YS50YWJsZTEgPSByb3cuVGFibGUyO1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnRhYmxlMiA9IHJvdy5UYWJsZTE7ICAgXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9KVxuXG4gICAgICAgIGNvbnNvbGUubG9nKCdEQVRBJyxkYXRhKTtcblxuICAgICAgICByZXR1cm4gJGh0dHAucHV0KCcvYXBpL2NsaWVudGRiL3J1bmpvaW4nLCBkYXRhKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpO1xuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS5nZXRQcmltYXJ5S2V5cyA9IGZ1bmN0aW9uKGlkLCBkYk5hbWUsIHRhYmxlTmFtZSwgY29sdW1ua2V5KXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9jbGllbnRkYi8nICsgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lICsgJy8nICsgaWQgKyBcIi9cIiArIGNvbHVtbmtleSlcbiAgICAgICAgLnRoZW4ocmVzVG9EYXRhKTtcbiAgICB9XG5cbiAgICBUYWJsZUZhY3RvcnkuZmluZFByaW1hcnkgPSBmdW5jdGlvbihkYk5hbWUsIHRibE5hbWUpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2NsaWVudGRiL3ByaW1hcnkvJytkYk5hbWUrJy8nK3RibE5hbWUpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LnNldEZvcmVpZ25LZXkgPSBmdW5jdGlvbihkYk5hbWUsIHRibE5hbWUsIGNvbE5hbWUsIGlkMSwgaWQyKXtcbiAgICAgICAgdmFyIGRhdGEgPSB7fTtcbiAgICAgICAgZGF0YS5kYk5hbWUgPSBkYk5hbWU7XG4gICAgICAgIGRhdGEudGJsTmFtZSA9IHRibE5hbWU7XG4gICAgICAgIGRhdGEuY29sTmFtZSA9IGNvbE5hbWU7XG4gICAgICAgIGRhdGEuaWQxID0gaWQxO1xuICAgICAgICBkYXRhLmlkMiA9IGlkMjtcblxuICAgICAgICByZXR1cm4gJGh0dHAucHV0KCcvYXBpL2NsaWVudGRiL3NldEZvcmVpZ25LZXknLCBkYXRhKVxuICAgICAgICAudGhlbihyZXNUb0RhdGEpOyAgIFxuICAgIH1cblxuICAgIFRhYmxlRmFjdG9yeS51cGRhdGVKb2luVGFibGUgPSBmdW5jdGlvbihkYk5hbWUsIHRhYmxlTmFtZSwgaWQsIG5ld1JvdywgdGFibGVUb1VwZGF0ZSwgY29sdW1uTmFtZSkge1xuICAgICAgICB2YXIgZGF0YSA9IHt9O1xuICAgICAgICBkYXRhLmRiTmFtZSA9IGRiTmFtZTtcbiAgICAgICAgZGF0YS50YmxOYW1lID0gdGFibGVOYW1lO1xuICAgICAgICBkYXRhLnJvd0lkID0gaWQ7XG4gICAgICAgIGRhdGEubmV3Um93ID0gbmV3Um93O1xuICAgICAgICBkYXRhLnRhYmxlVG9VcGRhdGUgPSB0YWJsZVRvVXBkYXRlO1xuICAgICAgICBkYXRhLmNvbHVtbk5hbWUgPSBjb2x1bW5OYW1lO1xuICAgICAgIFxuICAgICAgIHJldHVybiAkaHR0cC5wdXQoJy9hcGkvY2xpZW50ZGIvdXBkYXRlSm9pblRhYmxlJywgZGF0YSlcbiAgICAgICAudGhlbihyZXNUb0RhdGEpOyAgXG4gICAgfVxuXG4gICAgVGFibGVGYWN0b3J5LmluY3JlbWVudCA9IGZ1bmN0aW9uKGRiTmFtZSwgdGFibGVOYW1lKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5wdXQoJy9hcGkvY2xpZW50ZGIvJysgZGJOYW1lICsgJy8nICsgdGFibGVOYW1lICsnL2FkZHJvd29uam9pbicpXG4gICAgICAgIC50aGVuKHJlc1RvRGF0YSk7XG4gICAgfVxuXG5cdHJldHVybiBUYWJsZUZhY3Rvcnk7IFxufSkiLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZScsIHtcbiAgICAgICAgdXJsOiAnLzpkYk5hbWUnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL3RhYmxlLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnVGFibGVDdHJsJyxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICBcdGFsbFRhYmxlczogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldEFsbFRhYmxlcygkc3RhdGVQYXJhbXMuZGJOYW1lKTtcbiAgICAgICAgXHR9LCBcbiAgICAgICAgICAgIGFzc29jaWF0aW9uczogZnVuY3Rpb24oVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gVGFibGVGYWN0b3J5LmdldEFsbEFzc29jaWF0aW9ucygkc3RhdGVQYXJhbXMuZGJOYW1lKTtcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBhbGxDb2x1bW5zOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0QWxsQ29sdW1ucygkc3RhdGVQYXJhbXMuZGJOYW1lKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pO1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlLlNpbmdsZScsIHtcbiAgICAgICAgdXJsOiAnLzp0YWJsZU5hbWUnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3RhYmxlL3NpbmdsZXRhYmxlLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnU2luZ2xlVGFibGVDdHJsJyxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICAgICAgc2luZ2xlVGFibGU6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZSgkc3RhdGVQYXJhbXMuZGJOYW1lLCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKTtcbiAgICAgICAgICAgIH0sIFxuICAgICAgICAgICAgYXNzb2NpYXRpb25zOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0QXNzb2NpYXRpb25zKCRzdGF0ZVBhcmFtcy5kYk5hbWUsICRzdGF0ZVBhcmFtcy50YWJsZU5hbWUpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSk7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUuSm9pbicsIHtcbiAgICAgICAgdXJsOiAnLzp0YWJsZU5hbWUvOnJvd0lkLzprZXkvam9pbicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvam9pbi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ0pvaW5UYWJsZUN0cmwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgICBqb2luVGFibGU6IGZ1bmN0aW9uKFRhYmxlRmFjdG9yeSwgJHN0YXRlUGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRQcmltYXJ5S2V5cygkc3RhdGVQYXJhbXMucm93SWQsICRzdGF0ZVBhcmFtcy5kYk5hbWUsICRzdGF0ZVBhcmFtcy50YWJsZU5hbWUsICRzdGF0ZVBhcmFtcy5rZXkpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSk7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnVGFibGUuVGhyb3VnaCcsIHtcbiAgICAgICAgdXJsOiAnLzp0YWJsZU5hbWUvdGhyb3VnaCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvdGhyb3VnaC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Rocm91Z2hDdHJsJywgXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICAgIHNpbmdsZVRhYmxlOiBmdW5jdGlvbihUYWJsZUZhY3RvcnksICRzdGF0ZVBhcmFtcykge1xuICAgICAgICAgICAgICAgIHJldHVybiBUYWJsZUZhY3RvcnkuZ2V0U2luZ2xlVGFibGUoJHN0YXRlUGFyYW1zLmRiTmFtZSwgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KTsgIFxuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ1RhYmxlLmNyZWF0ZScsIHtcbiAgICAgICAgdXJsOiAnL2NyZWF0ZXRhYmxlJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9jcmVhdGV0YWJsZS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1RhYmxlQ3RybCdcbiAgICB9KTtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5zZXRBc3NvY2lhdGlvbicsIHtcbiAgICAgICAgdXJsOiAnL3NldGFzc29jaWF0aW9uJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS9zZXRhc3NvY2lhdGlvbi5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1RhYmxlQ3RybCdcbiAgICB9KTtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdUYWJsZS5TaW5nbGUucXVlcnknLCB7XG4gICAgICAgIHVybDogJy9xdWVyeXJlc3VsdCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvdGFibGUvcXVlcnkuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdRdWVyeVRhYmxlQ3RybCdcbiAgICB9KTsgICAgIFxuXG5cbn0pOyIsImFwcC5jb250cm9sbGVyKCdUaHJvdWdoQ3RybCcsIGZ1bmN0aW9uKCRzY29wZSwgVGFibGVGYWN0b3J5LCAkc3RhdGVQYXJhbXMsIGFzc29jaWF0aW9ucywgc2luZ2xlVGFibGUsICR1aWJNb2RhbCkge1xuXG4gICAgJHNjb3BlLmFzc29jaWF0aW9ucyA9IGFzc29jaWF0aW9ucztcbiAgICAkc2NvcGUudHdvVGFibGVzID0gW107XG4gICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gc2luZ2xlVGFibGVbMF07XG4gICAgJHNjb3BlLnRoZURiTmFtZSA9ICRzdGF0ZVBhcmFtcy5kYk5hbWU7XG4gICAgJHNjb3BlLnRhYmxlTmFtZSA9ICRzdGF0ZVBhcmFtcy50YWJsZU5hbWU7XG5cbiAgICBmdW5jdGlvbiBnZXQyVGFibGVzKCkge1xuICAgICAgICAkc2NvcGUuYXNzb2NpYXRpb25zLmZvckVhY2goZnVuY3Rpb24oYXNzb2MpIHtcbiAgICAgICAgICAgIGlmIChhc3NvY1snVGhyb3VnaCddID09PSAkc3RhdGVQYXJhbXMudGFibGVOYW1lKSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnR3b1RhYmxlcy5wdXNoKGFzc29jWydUYWJsZTEnXSk7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnR3b1RhYmxlcy5wdXNoKGFzc29jWydUYWJsZTInXSk7IC8vaGVyZSAtIGNvbWUgYmFja1xuICAgICAgICAgICAgfVxuICAgICAgICB9KVxuICAgIH1cblxuICAgIGdldDJUYWJsZXMoKTtcblxuICAgIGZ1bmN0aW9uIENyZWF0ZUNvbHVtbnMoKSB7XG4gICAgICAgICRzY29wZS5jb2x1bW5zID0gW107XG4gICAgICAgIHZhciB0YWJsZSA9IHNpbmdsZVRhYmxlWzBdWzBdO1xuICAgICAgICBmb3IgKHZhciBwcm9wIGluIHRhYmxlKSB7XG4gICAgICAgICAgICAkc2NvcGUuY29sdW1ucy5wdXNoKHByb3ApO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgQ3JlYXRlQ29sdW1ucygpO1xuXG5cbiAgICAvL3RoaXMgZnVuY3Rpb24gd2lsbCByZSBydW4gd2hlbiB0aGUgZmlsdGVyIGZ1bmN0aW9uIGlzIGludm9rZWQsIGluIG9yZGVyIHRvIHJlcG9wdWxhdGUgdGhlIHRhYmxlXG4gICAgZnVuY3Rpb24gQ3JlYXRlUm93cygpIHtcblxuICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheSA9IFtdO1xuICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUuZm9yRWFjaChmdW5jdGlvbihyb3cpIHtcbiAgICAgICAgICAgIHZhciByb3dWYWx1ZXMgPSBbXTtcbiAgICAgICAgICAgIGZvciAodmFyIHByb3AgaW4gcm93KSB7XG4gICAgICAgICAgICAgICAgcm93VmFsdWVzLnB1c2gocm93W3Byb3BdKVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkucHVzaChyb3dWYWx1ZXMpXG4gICAgICAgIH0pXG4gICAgfVxuXG4gICAgLy8gU29ydCB0aGUgdmFsdWVzIGluIHNpbmdsZVRhYmxlIHNvIHRoYXQgYWxsIHRoZSB2YWx1ZXMgZm9yIGEgZ2l2ZW4gcm93IGFyZSBncm91cGVkXG4gICAgQ3JlYXRlUm93cygpO1xuXG4gICAgLy8gJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkID0gdHJ1ZTtcblxuICAgICRzY29wZS5vcGVuID0gZnVuY3Rpb24oZGJOYW1lLCB0YWJsZU5hbWUsIGluZGV4LCByb3csIGNvbHVtbk5hbWUpIHtcbiAgICAgICAgY29uc29sZS5sb2coZGJOYW1lLCB0YWJsZU5hbWUsIGluZGV4LCByb3csIGNvbHVtbk5hbWUpO1xuICAgICAgICB2YXIgdGhlVGFibGUgPSAkc2NvcGUudHdvVGFibGVzW2luZGV4LTFdO1xuICAgICAgICBjb25zb2xlLmxvZygndHdvVGFibGVzJywgJHNjb3BlLnR3b1RhYmxlcyk7XG4gICAgICAgIGNvbnNvbGUubG9nKCd0aGVUYWJsZScsIHRoZVRhYmxlKTtcblxuICAgICAgICB2YXIgbW9kYWxJbnN0YW5jZSA9ICR1aWJNb2RhbC5vcGVuKHtcbiAgICAgICAgICAgIGFuaW1hdGlvbjogJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkLFxuICAgICAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy90YWJsZS90aHJvdWdoLm1vZGFsLmh0bWwnLFxuICAgICAgICAgICAgY29udHJvbGxlcjogJ1Rocm91Z2hNb2RhbEN0cmwnLFxuICAgICAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICAgICAgICAgIHRoZVRhYmxlOiBmdW5jdGlvbihUYWJsZUZhY3RvcnkpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFRhYmxlRmFjdG9yeS5nZXRTaW5nbGVUYWJsZShkYk5hbWUsIHRoZVRhYmxlKTtcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHRhYmxlTmFtZSA6IGZ1bmN0aW9uKCkgeyByZXR1cm4gdGhlVGFibGUgfSxcbiAgICAgICAgICAgICAgICByb3dJZCA6IGZ1bmN0aW9uKCkgeyByZXR1cm4gcm93IH0sXG4gICAgICAgICAgICAgICAgY29sdW1uTmFtZSA6IGZ1bmN0aW9uKCkgeyByZXR1cm4gY29sdW1uTmFtZSB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuXG4gICAgICAgIG1vZGFsSW5zdGFuY2UucmVzdWx0LnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkNMT1NFRFwiKVxuICAgICAgICAgICAgJHNjb3BlLiRldmFsQXN5bmMoKTtcbiAgICAgICAgfSk7XG4gICAgfTtcblxuICAgICRzY29wZS50b2dnbGVBbmltYXRpb24gPSBmdW5jdGlvbigpIHtcbiAgICAgICAgJHNjb3BlLmFuaW1hdGlvbnNFbmFibGVkID0gISRzY29wZS5hbmltYXRpb25zRW5hYmxlZDtcbiAgICB9O1xuXG4gICAgJHNjb3BlLm5ld1JvdyA9IGZ1bmN0aW9uKGRiLCB0YWJsZSkge1xuICAgICAgIFRhYmxlRmFjdG9yeS5pbmNyZW1lbnQoZGIsIHRhYmxlKVxuICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3VsdCkge1xuICAgICAgICBjb25zb2xlLmxvZyhyZXN1bHQpO1xuICAgICAgICAkc2NvcGUuaW5zdGFuY2VBcnJheSA9IHJlc3VsdDtcbiAgICAgICAgJHNjb3BlLiRldmFsQXN5bmMoKTtcbiAgICAgICB9KVxuICAgIH1cblxuICAgIC8vZGVsZXRlIGEgcm93IFxuICAgICRzY29wZS5zaG93RGVsZXRlID0gZmFsc2U7XG4gICAgJHNjb3BlLnRvZ2dsZURlbGV0ZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAkc2NvcGUuc2hvd0RlbGV0ZSA9ICEkc2NvcGUuc2hvd0RlbGV0ZVxuICAgIH1cblxuICAgICRzY29wZS5kZWxldGVTZWxlY3RlZCA9IGZ1bmN0aW9uKGRiLCB0YWJsZSwgaW5zdGFuY2VBcnJheSkge1xuICAgICAgICBpbnN0YW5jZUFycmF5LmZvckVhY2goZnVuY3Rpb24ocm93KSB7XG4gICAgICAgICAgICBpZiAocm93LnNlbGVjdGVkKSB7XG4gICAgICAgICAgICAgICAgVGFibGVGYWN0b3J5LnJlbW92ZVJvdyhkYiwgdGFibGUsIHJvd1swXSlcbiAgICAgICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAkc2NvcGUuc2luZ2xlVGFibGUgPSByZXN1bHQ7XG4gICAgICAgICAgICAgICAgICAgICAgICBDcmVhdGVSb3dzKCk7XG4gICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICB9XG4gICAgICAgIH0pXG4gICAgICAgICRzY29wZS5zaG93RGVsZXRlID0gZmFsc2U7XG4gICAgfVxuXG4gICAgJHNjb3BlLnNlbGVjdEFsbCA9IGZ1bmN0aW9uKGluc3RhbmNlQXJyYXkpIHtcbiAgICAgICAgaWYgKCRzY29wZS5zZWxlY3RlZEFsbCkge1xuICAgICAgICAgICAgaW5zdGFuY2VBcnJheS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgICAgIHJvdy5zZWxlY3RlZCA9IHRydWU7XG4gICAgICAgICAgICB9KVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgaW5zdGFuY2VBcnJheS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgICAgIHJvdy5zZWxlY3RlZCA9IGZhbHNlO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS51bmNoZWNrU2VsZWN0QWxsID0gZnVuY3Rpb24oaW5zdGFuY2VBcnJheSkge1xuICAgICAgICBpZiAoJHNjb3BlLnNlbGVjdGVkQWxsID09PSB0cnVlKSB7XG4gICAgICAgICAgICAkc2NvcGUuc2VsZWN0ZWRBbGwgPSBmYWxzZTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgICRzY29wZS5yZW1vdmVSb3cgPSBmdW5jdGlvbihkYiwgdGFibGUsIHJvdykge1xuICAgICAgICBUYWJsZUZhY3RvcnkucmVtb3ZlUm93KGRiLCB0YWJsZSwgcm93KVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24ocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnNpbmdsZVRhYmxlID0gcmVzdWx0O1xuICAgICAgICAgICAgICAgIENyZWF0ZVJvd3MoKTtcbiAgICAgICAgICAgIH0pXG4gICAgfVxuXG4gICAgJHNjb3BlLmNzdiA9IGZ1bmN0aW9uKHRhYmxlKXtcbiAgICAgICAgYWxhc3FsKFwiU0VMRUNUICogSU5UTyBDU1YoJ215ZGF0YS5jc3YnLCB7aGVhZGVyczp0cnVlfSkgRlJPTSA/XCIsW3RhYmxlXSk7XG4gICAgfSAgICBcblxufSlcbiIsImFwcC5jb250cm9sbGVyKCdUaHJvdWdoTW9kYWxDdHJsJywgZnVuY3Rpb24oJHNjb3BlLCAkdWliTW9kYWxJbnN0YW5jZSwgVGFibGVGYWN0b3J5LCBIb21lRmFjdG9yeSwgJHN0YXRlUGFyYW1zLCAkc3RhdGUsIHRoZVRhYmxlLCB0YWJsZU5hbWUsIHJvd0lkLCBjb2x1bW5OYW1lKSB7XG5cbiAgICAkc2NvcGUuZGJOYW1lID0gJHN0YXRlUGFyYW1zLmRiTmFtZTtcblxuICAgICRzY29wZS5zaW5nbGVUYWJsZSA9IHRoZVRhYmxlO1xuXG4gICAgJHNjb3BlLnRhYmxlTmFtZSA9IHRhYmxlTmFtZTtcblxuICAgICRzY29wZS5yb3dJZCA9IHJvd0lkO1xuXG4gICAgJHNjb3BlLmNvbHVtbk5hbWUgPSBjb2x1bW5OYW1lO1xuXG4gICAgJHNjb3BlLnNldFNlbGVjdGVkID0gZnVuY3Rpb24oKSB7XG5cbiAgICAgICAgJHNjb3BlLmN1cnJSb3cgPSB0aGlzLnJvdztcbiAgICAgICAgLy8gY29uc29sZS5sb2coJ0hFUkUnLCAkc2NvcGUuY3VyclJvdyk7XG4gICAgfVxuXG5cbiAgICAvLyBjb25zb2xlLmxvZygkc2NvcGUuc2luZ2xlVGFibGVbMF0pXG4gICAgZnVuY3Rpb24gQ3JlYXRlQ29sdW1ucygpIHtcbiAgICAgICAgJHNjb3BlLmNvbHVtbnMgPSBbXTtcbiAgICAgICAgdmFyIHRhYmxlID0gJHNjb3BlLnNpbmdsZVRhYmxlWzBdWzBdO1xuXG5cbiAgICAgICAgZm9yICh2YXIgcHJvcCBpbiB0YWJsZSkge1xuICAgICAgICAgICAgaWYgKHByb3AgIT09ICdjcmVhdGVkX2F0JyAmJiBwcm9wICE9PSAndXBkYXRlZF9hdCcpIHtcbiAgICAgICAgICAgICAgICAkc2NvcGUuY29sdW1ucy5wdXNoKHByb3ApO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgQ3JlYXRlQ29sdW1ucygpO1xuXG4gICAgLy90aGlzIGZ1bmN0aW9uIHdpbGwgcmUgcnVuIHdoZW4gdGhlIGZpbHRlciBmdW5jdGlvbiBpcyBpbnZva2VkLCBpbiBvcmRlciB0byByZXBvcHVsYXRlIHRoZSB0YWJsZVxuICAgIGZ1bmN0aW9uIENyZWF0ZVJvd3MoKSB7XG4gICAgICAgICRzY29wZS5pbnN0YW5jZUFycmF5ID0gW107XG4gICAgICAgICRzY29wZS5zaW5nbGVUYWJsZVswXS5mb3JFYWNoKGZ1bmN0aW9uKHJvdykge1xuICAgICAgICAgICAgdmFyIHJvd1ZhbHVlcyA9IFtdO1xuICAgICAgICAgICAgZm9yICh2YXIgcHJvcCBpbiByb3cpIHtcbiAgICAgICAgICAgICAgICBpZiAocHJvcCAhPT0gJ2NyZWF0ZWRfYXQnICYmIHByb3AgIT09ICd1cGRhdGVkX2F0Jykgcm93VmFsdWVzLnB1c2gocm93W3Byb3BdKVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgJHNjb3BlLmluc3RhbmNlQXJyYXkucHVzaChyb3dWYWx1ZXMpXG4gICAgICAgIH0pXG4gICAgfVxuXG4gICAgLy8gU29ydCB0aGUgdmFsdWVzIGluIHNpbmdsZVRhYmxlIHNvIHRoYXQgYWxsIHRoZSB2YWx1ZXMgZm9yIGEgZ2l2ZW4gcm93IGFyZSBncm91cGVkXG4gICAgQ3JlYXRlUm93cygpO1xuXG5cbiAgICAkc2NvcGUuc2V0Rm9yZWlnbktleSA9IGZ1bmN0aW9uKGRiTmFtZSwgdGJsTmFtZSwgcm93SWQsIG5ld1Jvdykge1xuICAgICAgICAkdWliTW9kYWxJbnN0YW5jZS5jbG9zZSgpO1xuICAgICAgICBjb25zb2xlLmxvZygnSEVSRScsICRzY29wZS5jb2x1bW5OYW1lKTtcbiAgICAgICAgY29uc29sZS5sb2coZGJOYW1lLCB0YmxOYW1lLCByb3dJZCwgbmV3Um93LCAkc3RhdGVQYXJhbXMudGFibGVOYW1lKVxuICAgICAgICBUYWJsZUZhY3RvcnkudXBkYXRlSm9pblRhYmxlKGRiTmFtZSwgdGJsTmFtZSwgcm93SWQsIG5ld1JvdywgJHN0YXRlUGFyYW1zLnRhYmxlTmFtZSwgJHNjb3BlLmNvbHVtbk5hbWUpO1xuICAgICAgICAgICAgLy8gLnRoZW4oZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAvLyAgICAgLy8gJHN0YXRlLmdvKCdUYWJsZS5TaW5nbGUnLCB7IGRiTmFtZTogJHNjb3BlLmRiTmFtZSwgdGFibGVOYW1lOiAkc2NvcGUuc2luZ2xlVGFibGUgfSwgeyByZWxvYWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC8vIH0pXG4gICAgfVxuXG5cblxuICAgICRzY29wZS5vayA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAkdWliTW9kYWxJbnN0YW5jZS5jbG9zZSgkc2NvcGUuc2VsZWN0ZWQuaXRlbSk7XG4gICAgfTtcblxuICAgICRzY29wZS5jYW5jZWwgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgJHVpYk1vZGFsSW5zdGFuY2UuZGlzbWlzcygnY2FuY2VsJyk7XG4gICAgfTtcbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ0Z1bGxzdGFja1BpY3MnLCBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIFtcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CN2dCWHVsQ0FBQVhRY0UuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vZmJjZG4tc3Bob3Rvcy1jLWEuYWthbWFpaGQubmV0L2hwaG90b3MtYWsteGFwMS90MzEuMC04LzEwODYyNDUxXzEwMjA1NjIyOTkwMzU5MjQxXzgwMjcxNjg4NDMzMTI4NDExMzdfby5qcGcnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0ItTEtVc2hJZ0FFeTlTSy5qcGcnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I3OS1YN29DTUFBa3c3eS5qcGcnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0ItVWo5Q09JSUFJRkFoMC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I2eUl5RmlDRUFBcWwxMi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFLVQ3NWxXQUFBbXFxSi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFdlpBZy1WQUFBazkzMi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFZ05NZU9YSUFJZkRoSy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NFUXlJRE5XZ0FBdTYwQi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NDRjNUNVFXOEFFMmxHSi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NBZVZ3NVNXb0FBQUxzai5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NBYUpJUDdVa0FBbElHcy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NBUU93OWxXRUFBWTlGbC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0ItT1FiVnJDTUFBTndJTS5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I5Yl9lcndDWUFBd1JjSi5wbmc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I1UFRkdm5DY0FFQWw0eC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0I0cXdDMGlDWUFBbFBHaC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0IyYjMzdlJJVUFBOW8xRC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0J3cEl3cjFJVUFBdk8yXy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0JzU3NlQU5DWUFFT2hMdy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NKNHZMZnVVd0FBZGE0TC5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NJN3d6akVWRUFBT1BwUy5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NJZEh2VDJVc0FBbm5IVi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NHQ2lQX1lXWUFBbzc1Vi5qcGc6bGFyZ2UnLFxuICAgICAgICAnaHR0cHM6Ly9wYnMudHdpbWcuY29tL21lZGlhL0NJUzRKUElXSUFJMzdxdS5qcGc6bGFyZ2UnXG4gICAgXTtcbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ1JhbmRvbUdyZWV0aW5ncycsIGZ1bmN0aW9uICgpIHtcblxuICAgIHZhciBnZXRSYW5kb21Gcm9tQXJyYXkgPSBmdW5jdGlvbiAoYXJyKSB7XG4gICAgICAgIHJldHVybiBhcnJbTWF0aC5mbG9vcihNYXRoLnJhbmRvbSgpICogYXJyLmxlbmd0aCldO1xuICAgIH07XG5cbiAgICB2YXIgZ3JlZXRpbmdzID0gW1xuICAgICAgICAnSGVsbG8sIHdvcmxkIScsXG4gICAgICAgICdBdCBsb25nIGxhc3QsIEkgbGl2ZSEnLFxuICAgICAgICAnSGVsbG8sIHNpbXBsZSBodW1hbi4nLFxuICAgICAgICAnV2hhdCBhIGJlYXV0aWZ1bCBkYXkhJyxcbiAgICAgICAgJ0lcXCdtIGxpa2UgYW55IG90aGVyIHByb2plY3QsIGV4Y2VwdCB0aGF0IEkgYW0geW91cnMuIDopJyxcbiAgICAgICAgJ1RoaXMgZW1wdHkgc3RyaW5nIGlzIGZvciBMaW5kc2F5IExldmluZS4nLFxuICAgICAgICAn44GT44KT44Gr44Gh44Gv44CB44Om44O844K244O85qeY44CCJyxcbiAgICAgICAgJ1dlbGNvbWUuIFRvLiBXRUJTSVRFLicsXG4gICAgICAgICc6RCcsXG4gICAgICAgICdZZXMsIEkgdGhpbmsgd2VcXCd2ZSBtZXQgYmVmb3JlLicsXG4gICAgICAgICdHaW1tZSAzIG1pbnMuLi4gSSBqdXN0IGdyYWJiZWQgdGhpcyByZWFsbHkgZG9wZSBmcml0dGF0YScsXG4gICAgICAgICdJZiBDb29wZXIgY291bGQgb2ZmZXIgb25seSBvbmUgcGllY2Ugb2YgYWR2aWNlLCBpdCB3b3VsZCBiZSB0byBuZXZTUVVJUlJFTCEnLFxuICAgIF07XG5cbiAgICByZXR1cm4ge1xuICAgICAgICBncmVldGluZ3M6IGdyZWV0aW5ncyxcbiAgICAgICAgZ2V0UmFuZG9tR3JlZXRpbmc6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiBnZXRSYW5kb21Gcm9tQXJyYXkoZ3JlZXRpbmdzKTtcbiAgICAgICAgfVxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZSgnZnVsbHN0YWNrTG9nbycsIGZ1bmN0aW9uICgpIHtcbiAgICByZXR1cm4ge1xuICAgICAgICByZXN0cmljdDogJ0UnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL2Z1bGxzdGFjay1sb2dvL2Z1bGxzdGFjay1sb2dvLmh0bWwnXG4gICAgfTtcbn0pOyIsImFwcC5kaXJlY3RpdmUoJ3NpZGViYXInLCBmdW5jdGlvbiAoJHJvb3RTY29wZSwgQXV0aFNlcnZpY2UsIEFVVEhfRVZFTlRTLCAkc3RhdGUpIHtcblxuICAgIHJldHVybiB7XG4gICAgICAgIHJlc3RyaWN0OiAnRScsXG4gICAgICAgIHNjb3BlOiB7fSxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9uYXZiYXIvbmF2YmFyLmh0bWwnLFxuICAgICAgICBsaW5rOiBmdW5jdGlvbiAoc2NvcGUpIHtcblxuICAgICAgICAgICAgc2NvcGUuaXRlbXMgPSBbXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ0hvbWUnLCBzdGF0ZTogJ2hvbWUnIH0sXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ0Fib3V0Jywgc3RhdGU6ICdhYm91dCcgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnRG9jdW1lbnRhdGlvbicsIHN0YXRlOiAnZG9jcycgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnTWVtYmVycyBPbmx5Jywgc3RhdGU6ICdtZW1iZXJzT25seScsIGF1dGg6IHRydWUgfVxuICAgICAgICAgICAgXTtcblxuICAgICAgICAgICAgc2NvcGUudXNlciA9IG51bGw7XG5cbiAgICAgICAgICAgIHNjb3BlLmlzTG9nZ2VkSW4gPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgc2NvcGUubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIEF1dGhTZXJ2aWNlLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnbGFuZGluZ1BhZ2UnKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHZhciBzZXRVc2VyID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpLnRoZW4oZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgICAgICAgICAgICAgc2NvcGUudXNlciA9IHVzZXI7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICB2YXIgcmVtb3ZlVXNlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBzY29wZS51c2VyID0gbnVsbDtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHNldFVzZXIoKTtcblxuICAgICAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMubG9naW5TdWNjZXNzLCBzZXRVc2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLmxvZ291dFN1Y2Nlc3MsIHJlbW92ZVVzZXIpO1xuICAgICAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsIHJlbW92ZVVzZXIpO1xuXG4gICAgICAgIH1cblxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZSgncmFuZG9HcmVldGluZycsIGZ1bmN0aW9uIChSYW5kb21HcmVldGluZ3MpIHtcblxuICAgIHJldHVybiB7XG4gICAgICAgIHJlc3RyaWN0OiAnRScsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvY29tbW9uL2RpcmVjdGl2ZXMvcmFuZG8tZ3JlZXRpbmcvcmFuZG8tZ3JlZXRpbmcuaHRtbCcsXG4gICAgICAgIGxpbms6IGZ1bmN0aW9uIChzY29wZSkge1xuICAgICAgICAgICAgc2NvcGUuZ3JlZXRpbmcgPSBSYW5kb21HcmVldGluZ3MuZ2V0UmFuZG9tR3JlZXRpbmcoKTtcbiAgICAgICAgfVxuICAgIH07XG5cbn0pOyJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
