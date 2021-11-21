<template>
  <el-card v-loading="loading" style="height: 89vh" class="box-card">
    <el-tabs v-model="active">
      <el-tab-pane label="General" name="general">
        <General v-bind:ps="ps"/>
      </el-tab-pane>

      <el-tab-pane label="Modules" name="modules">
        <Modules v-bind:modules="ps.modules"></Modules>
      </el-tab-pane>

      <el-tab-pane label="Events" name="events">
      </el-tab-pane>
    </el-tabs>
  </el-card>
</template>

<script>
import axios from "axios";
import {ElMessage} from "element-plus";
import General from "@/components/ps/tab/General";
import Modules from "@/components/ps/tab/Modules";

export default {
  components: {Modules, General},
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
    }
  },
  created() {
    this.fetchProcess()
  }
}
</script>

<style>
.header-row {
  font-weight: 500;
  font-size: 13px;
}
</style>
