app.config(function ($stateProvider) {
    $stateProvider.state('Query', {
        url: '/query',
        templateUrl: 'js/query/query.html',
        controller: 'QueryCtrl'
        }
    );

});