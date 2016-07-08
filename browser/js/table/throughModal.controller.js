app.controller('ThroughModalCtrl', function ($scope, $uibModalInstance, TableFactory, HomeFactory, $stateParams, $state, theTable) {

  $scope.dbName = $stateParams.dbName;

  $scope.singleTable = theTable;

  

  $scope.setSelected = function(){

    $scope.currRow = this.row;
    console.log($scope.currRow);
  }

 

  function CreateColumns(){
    $scope.columns = [];
    var table = $scope.singleTable[0];


    for(var prop in table){
      if(prop !== 'created_at' && prop !== 'updated_at'){
        $scope.columns.push(prop);  
      } 
    }
  }

    CreateColumns();


    //this function will re run when the filter function is invoked, in order to repopulate the table
    function CreateRows() {
        $scope.instanceArray = [];
        $scope.singleTable[0].forEach(function(row) {
            var rowValues = [];
            for (var prop in row) {
                if (prop !== 'created_at' && prop !== 'updated_at') rowValues.push(row[prop])
            }
            $scope.instanceArray.push(rowValues)
        })
    }

    // Sort the values in singleTable so that all the values for a given row are grouped
    CreateRows();


  $scope.setForeignKey = function(dbName, tblName, colName, id1, id2){
    $uibModalInstance.close();
    TableFactory.setForeignKey(dbName, tblName, colName, id1, id2)
    .then(function(){
        $state.go('Table.Single', { dbName: $scope.dbName, tableName: $scope.singleTable }, { reload: true })
    })
  }



  $scope.ok = function () {
    $uibModalInstance.close($scope.selected.item);
  };

  $scope.cancel = function () {
    $uibModalInstance.dismiss('cancel');
  };
});