<template>
  <el-card class="box-card">
    <el-table
      row-key="pid"
      v-loading="loading"
      header-row-class-name="header-row"
      :data="processes"
      style="width: 100%; height: 95%"
      lazy
    >

      <el-table-column sortable prop="exe" label="EXE" width="280"/>
      <el-table-column sortable prop="pid" label="PID" width="100"/>
      <el-table-column align="right">
        <template #header>
          <el-input v-model="search" size="small" clearable prefix-icon="el-icon-search" placeholder="Type to search" />
        </template>
      </el-table-column>
    </el-table>
    <el-pagination background layout="prev, pager, next" :total="this.processes.length" @current-change="setPage"/>
  </el-card>
</template>

<script>
import axios from "axios";
import { ElMessage } from 'element-plus'

export default {
  name: "Processes",
  data() {
    return {
      pageSize: 10,
      page: 1,
      processes: [],
      loading: true,
      search: ''
    }
  },
  methods: {
    getProcesses() {
      axios.get('http://localhost:8081/processes')
        .then((res) => {
          this.processes = JSON.parse(JSON.stringify([{pid: res.data.pid, children: res.data.children}]));
          this.loading = false
        })
        .catch((error) => {
          ElMessage.error({showClose: true, message: error, type: 'error'})
          this.loading = false
        })
    },
    setPage(page) {
      this.page = page
    },
  },
  created() {
    this.getProcesses()
  },
  computed: {
    filteredProcesses() {
      return this.processes.slice(this.pageSize * this.page - this.pageSize, this.pageSize * this.page)
    }
  }
}
</script>

<style>

.el-pagination {
  align-content: center !important;
}

.header-row {
  font-weight: 500;
  font-size: 15px;
}

</style>

