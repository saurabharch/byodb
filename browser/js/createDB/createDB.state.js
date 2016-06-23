app.config(function ($stateProvider) {
    $stateProvider.state('createDB', {
        url: '/createdb',
        templateUrl: 'js/createDB/createDB.html',
        controller: 'CreateDBCtrl'
        }
    );
});
