<template>
  <el-card class="box-card">
    <el-row>
      <el-col>
        <el-input v-model="term" clearable prefix-icon="el-icon-search" placeholder="Search processes..."/>
      </el-col>
    </el-row>
    <el-row>
      <el-col>
        <el-table
          id="processes"
          class="scroller"
          row-key="id"
          :row-class-name="tableRowClassName"
          @row-click="openProcess"
          cell-class-name="table-cell"
          v-loading="loading"
          default-expand-all
          empty-text="No processes"
          header-row-class-name="header-row"
          :data="search"
          style="width: 100%;"
          height="78vh">

          <el-table-column label="NAME" width="580">
            <template #default="scope">
              <el-tooltip placement="top">
                <template v-slot:content>
                  <span v-if="scope.row.ps">Path: {{ scope.row.ps.exe }}</span>
                </template>
                <ion-icon name="terminal" style="display:inline-block;position: relative; top: 2px;"></ion-icon>
              </el-tooltip>
              <span v-if="scope.row.ps" style="margin-left: 10px; font-weight: 500">{{ scope.row.ps.name }}</span>
            </template>
          </el-table-column>

          <el-table-column prop="pid" label="PID" width="100px"/>
          <el-table-column prop="ps.sid" label="USER" width="300px"/>
          <el-table-column prop="ps.start_time" label="START TIME"/>

        </el-table>
      </el-col>
    </el-row>

  </el-card>
</template>

<script>
import axios from "axios";
import {ElMessage} from 'element-plus'

export default {
  name: "Processes",
  data() {
    return {
      processes: [],
      loading: true,
      term: ''
    }
  },
  methods: {
    fetchTree() {
      axios.get('http://localhost:8081/processes')
        .then((res) => {
          this.processes = res.data
          this.loading = false
        })
        .catch((error) => {
          ElMessage.error({showClose: true, message: error, type: 'error'})
          this.loading = false
        })
    },
    // eslint-disable-next-line no-unused-vars
    openProcess(row, column, event) {
      this.$router.push({name: 'process', path: `/processes/${row.pid}`, params: {pid: row.pid}})
    },
    // eslint-disable-next-line no-unused-vars
    tableRowClassName({row, rowIndex}) {

      if (row.ps && row.ps.name === 'svchost.exe') {
        return 'success-row'
      }
      return '';

    },
    findNodes(children) {
      let processes = []
      children.forEach(node => {
        if (node.ps.name.toLowerCase().includes(this.term.toLowerCase())) {
          processes.push({ps: node.ps, pid: node.ps.pid, id: node.id})
        }
        processes = processes.concat(this.findNodes(node.children))
      })
      return processes
    },
  },
  created() {
    this.fetchTree()
  },
  computed: {
    search() {
      if (!this.term.length || this.term.length < 2) {
        return this.processes
      }
      let processes = []
      this.processes.forEach(ps => {
        processes = processes.concat(this.findNodes(ps.children))
      })
      return processes
    }
  }
}
</script>

<style>
.header-row {
  font-weight: 400;
  font-size: 12px;
}

.table-row {
  border: none !important;
  font-size: 9px !important;

}

.table-cell {
  border: transparent !important;
  padding: 2px !important;
  border-radius: 2px;
  cursor: pointer;
}

table {
  border-collapse: separate;
  border-spacing: 0 5px;
}

.warning-row {
  background-color: red;
}

.success-row td {
  background-color: #fdf2f5 !important;

}

.success-row td:first-child {
  border-radius: 15px 0 0 15px;

}

.success-row td:last-child {
  border-radius: 0 15px 15px 0;

}

.el-table__body-wrapper {
  scrollbar-color: #7f7f7f white;
  scrollbar-width: thin;
}

.scroller::-webkit-scrollbar {
  width: 7.5px;
}

.scroller::-webkit-scrollbar-track {
  background: white;
}

.scroller::-webkit-scrollbar-thumb {
  background: #7f7f7f;
  border-right: 1px solid white;
}

</style>

