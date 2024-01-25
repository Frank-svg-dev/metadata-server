package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/coreos/etcd/clientv3"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	virtv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	//kubernetesClient := GetKubernetesClientSet(clusterConfig)
	//clusterConfig, err := rest.InClusterConfig()
	clusterConfig, err := clientcmd.BuildConfigFromFlags("", "/root/.kube/config")
	if err != nil {
		panic(err)
	}
	clientSet := GetKubevirtClientSet(clusterConfig)
	etcdClient := BuildEtcdClient()
	defer etcdClient.Close()
	r := gin.Default()

	// 测试路由
	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	r.POST("/kubevirt/latest/user-data", func(c *gin.Context) {
		password := c.Query("password")
		if password == "" {
			c.String(http.StatusBadRequest, "password is valid")
		}
		instanceIp := GetRequestIp(c)
		instance, err := GetInstanceInformation(clientSet, instanceIp)
		if err != nil || instance == nil {
			log.Println("get instance information failed: ", err)
			c.String(http.StatusInternalServerError, "Internal Server Error")
		}
		//通过etcd去获取对应的map并返回， 只支持Root账号, 并配有base64硬编码

		key := fmt.Sprintf("/kubevirt/%s/%s", instance.Namespace, instance.Name)
		value := base64.StdEncoding.EncodeToString([]byte(password))
		response, err := etcdClient.Put(context.TODO(), key, value)
		if err != nil || response == nil {
			log.Println("get instance user_data failed: ", err)
			c.String(http.StatusInternalServerError, "Internal Server Error")
		}

		c.String(http.StatusOK, "%s/%s root pass inject success ", instance.Namespace, instance.Name)
	})

	r.GET("/kubevirt/latest/user-data", func(c *gin.Context) {
		instanceIp := GetRequestIp(c)
		instance, err := GetInstanceInformation(clientSet, instanceIp)
		if err != nil || instance == nil {
			log.Println("get instance information failed: ", err)
			c.String(http.StatusInternalServerError, "Internal Server Error")
		}
		//通过etcd去获取对应的map并返回， 只支持Root账号
		//pp-dashboard-api中直接写入mysql数据库，并配有base64硬编码

		key := fmt.Sprintf("/kubevirt/%s/%s", instance.Namespace, instance.Name)
		response, err := etcdClient.Get(context.TODO(), key)
		if err != nil || response == nil {
			log.Println("get instance user_data failed: ", err)
			c.String(http.StatusInternalServerError, "Internal Server Error")
		}

		for _, kv := range response.Kvs {
			password, err := base64.StdEncoding.DecodeString(string(kv.Value))

			if err != nil {
				log.Println("password base64 decode failed: ", err)
				c.String(http.StatusInternalServerError, "Internal Server Error")
			}

			c.JSON(http.StatusOK, &RootPassRes{
				Username: "root",
				Password: string(password),
			})
		}
	})

	metaRoute := r.Group("/kubevirt/latest/meta-data")
	metaRoute.GET("", func(c *gin.Context) {
		//通过yaml获取信息, 然后放在这个地方
	})

	metaRoute.GET("hostname", func(c *gin.Context) {
		instanceIp := GetRequestIp(c)
		instance, err := GetInstanceInformation(clientSet, instanceIp)
		if err != nil || instance == nil {
			log.Println("get instance information failed: ", err)
			c.String(http.StatusInternalServerError, "Internal Server Error")
		}

		c.String(http.StatusOK, ReplaceUpper2Lower(instance.Name))
	})

	metaRoute.GET("instance-type", func(c *gin.Context) {
		instanceIp := GetRequestIp(c)
		instance, err := GetInstanceInformation(clientSet, instanceIp)
		if err != nil || instance == nil {
			log.Println("get instance information failed: ", err)
			c.String(http.StatusInternalServerError, "Internal Server Error")
		}

		c.String(http.StatusOK, fmt.Sprintf("%dC——%sG\n",
			instance.Spec.Domain.CPU.Cores, instance.Spec.Domain.Resources.Requests.Memory().String()))
	})
	// 启动服务器
	r.Run(":8080")
}

func BuildEtcdClient() *clientv3.Client {

	caCert, err := ioutil.ReadFile("/etc/kubernetes/pki/etcd/ca.crt")
	if err != nil {
		panic(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	serverCert, err := tls.LoadX509KeyPair("/etc/kubernetes/pki/apiserver-etcd-client.crt", "/etc/kubernetes/pki/apiserver-etcd-client.key")
	if err != nil {
		panic(err)
	}

	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"192.168.223.18:2379"}, //节点
		DialTimeout: 10 * time.Second,                //超过10秒钟连不上超时
		TLS: &tls.Config{
			RootCAs:      caCertPool,
			Certificates: []tls.Certificate{serverCert},
		},
	})

	if err != nil {
		log.Println("connect to etcd failed:", err)
		panic(err)
	}
	log.Println("connect to etcd success")
	return client
}

func GetKubevirtClientSet(config *rest.Config) kubecli.KubevirtClient {
	clientSet, err := kubecli.GetKubevirtClientFromRESTConfig(config)
	if err != nil {
		panic(err)
	}
	return clientSet
}

func GetInstanceInformation(clientSet kubecli.KubevirtClient, instanceIp string) (*virtv1.VirtualMachineInstance, error) {
	instances, err := clientSet.VirtualMachineInstance("").List(context.Background(), &metav1.ListOptions{})
	if err != nil {
		log.Println("get all instance information failed: ", err)
		return &virtv1.VirtualMachineInstance{}, err
	}
	for _, instance := range instances.Items {
		for _, netCard := range instance.Status.Interfaces {
			if netCard.IP == instanceIp {
				return &instance, nil
			}
		}
	}
	return &virtv1.VirtualMachineInstance{}, err
}

func ReplaceUpper2Lower(str string) string {
	return strings.ToLower(str)
}

func GetRequestIp(c *gin.Context) string {
	ip := c.Request.Header.Get("X-Real-IP")
	if ip == "" {
		ip = c.Request.Header.Get("X-Forwarded-For")
	}

	if ip == "" {
		ip = c.Request.RemoteAddr

	}
	return ip
}
