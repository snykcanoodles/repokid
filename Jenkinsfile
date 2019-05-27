pipeline {
    agent {
        label 'ecs-gopro'
    }

    stages {
        stage('Build repokid image') {
            steps {
                sh 'wget -o /dev/null -O /tmp/docker.tgz https://download.docker.com/linux/static/stable/x86_64/docker-17.09.1-ce.tgz'
                sh 'tar zxvf /tmp/docker.tgz -C /tmp'
                sh 'sudo cp /tmp/docker/* /usr/bin/'
                sh 'sudo chmod u+s /usr/bin/docker'
                script {
                    sh 'ls -l'
                    dir("${WORKSPACE}") {
                        app = docker.build("repokid:${BUILD_NUMBER}", ".")
                        docker.withRegistry("${ART_SERVER}", 'a90b9141-9b65-4652-9ce0-4394bcd9da0c') {
                            app.push("${env.BUILD_NUMBER}")
                            app.push("latest")
                        }
                    }
                }
            }
        }
    }
}
