app.controller('DeleteDbCtrl', function ($scope) {

  $scope.animationsEnabled = true;

  $scope.open = function (size) {

    var modalInstance = $uibModal.open({
      animation: $scope.animationsEnabled,
      templateUrl: 'deleteDbContent.html',
      controller: 'DeleteDbInstanceCtrl',
      size: size,
      resolve: {
        items: function () {
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

  $scope.dbName = $stateParams.dbName

  $scope.dropDatabase = 'DROP DATABASE'

  $scope.delete = function () {
    TableFactory.deleteDb($scope.dbName)
    $state.go('Home', {}, {reload : true})
  };

  $scope.cancel = function () {
    $uibModalInstance.dismiss('cancel');
  };
});