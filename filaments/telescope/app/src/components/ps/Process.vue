<template>
  <el-card v-loading="loading" style="height: 89vh" class="box-card">
    <el-tabs v-model="active">
      <el-tab-pane label="General" name="general">
        <el-form ref="form" :model="ps" label-width="120px" size="mini">
          <el-form-item label="Name">
            <el-input disabled v-model="ps.name">
              <template #append>
                <el-button icon="search"></el-button>
              </template>
            </el-input>
          </el-form-item>
          <el-form-item label="Path">
            <el-input disabled v-model="ps.exe">
              <template #append>
                <el-button :icon="document-copy"></el-button>
              </template>
            </el-input>
          </el-form-item>
        </el-form>
      </el-tab-pane>
      <el-tab-pane label="Modules" name="modules">Modules</el-tab-pane>
    </el-tabs>
  </el-card>
</template>

<script>
import axios from "axios";
import {ElMessage} from "element-plus";

export default {
  props: ['pid'],
  data() {
    return {
      active: 'general',
      loading: true,
      ps: {}
    }
  },
  methods: {
    fetchProcess() {
      axios.get(`http://localhost:8081/processes/${this.pid}`)
        .then((res) => {
          this.ps = res.data
          this.loading = false
        })
        .catch((error) => {
          ElMessage.error({showClose: true, message: error, type: 'error'})
          this.loading = false
        })
    },
  },
  created() {
    this.fetchProcess()
  }
}
</script>
