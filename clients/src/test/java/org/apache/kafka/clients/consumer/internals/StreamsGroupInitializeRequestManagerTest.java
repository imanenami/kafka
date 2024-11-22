/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kafka.clients.consumer.internals;

import org.apache.kafka.common.Node;
import org.apache.kafka.common.message.StreamsGroupInitializeRequestData;
import org.apache.kafka.common.protocol.ApiKeys;
import org.apache.kafka.common.requests.StreamsGroupInitializeRequest;
import org.apache.kafka.common.utils.LogContext;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.apache.kafka.common.utils.Utils.mkEntry;
import static org.apache.kafka.common.utils.Utils.mkMap;
import static org.apache.kafka.common.utils.Utils.mkSet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StreamsGroupInitializeRequestManagerTest {

    private final String groupId = "groupId";
    private final LogContext logContext = new LogContext("test");

    @Test
    public void shouldPollEmptyResult() {
        final CoordinatorRequestManager coordinatorRequestManager = mock(CoordinatorRequestManager.class);
        final StreamsAssignmentInterface streamsAssignmentInterface = mock(StreamsAssignmentInterface.class);
        final StreamsGroupInitializeRequestManager streamsGroupInitializeRequestManager = new StreamsGroupInitializeRequestManager(
            logContext,
            groupId,
            streamsAssignmentInterface,
            coordinatorRequestManager
        );

        final NetworkClientDelegate.PollResult pollResult = streamsGroupInitializeRequestManager.poll(0);

        assertEquals(NetworkClientDelegate.PollResult.EMPTY, pollResult);
    }

    @Test
    public void shouldPollStreamsGroupInitializeRequest() {
        final Node node = mock(Node.class);
        final CoordinatorRequestManager coordinatorRequestManager = mock(CoordinatorRequestManager.class);
        when(coordinatorRequestManager.coordinator()).thenReturn(Optional.of(node));
        final StreamsAssignmentInterface streamsAssignmentInterface = mock(StreamsAssignmentInterface.class);
        final Set<String> sourceTopics = mkSet("sourceTopic1", "sourceTopic2");
        final Set<String> sinkTopics = mkSet("sinkTopic1", "sinkTopic2", "sinkTopic3");
        final Map<String, StreamsAssignmentInterface.TopicInfo> repartitionTopics = mkMap(
            mkEntry("repartitionTopic1", new StreamsAssignmentInterface.TopicInfo(Optional.of(2), Optional.of((short) 1), Collections.emptyMap())),
            mkEntry("repartitionTopic2", new StreamsAssignmentInterface.TopicInfo(Optional.of(3), Optional.of((short) 3), Collections.emptyMap()))
        );
        final Map<String, StreamsAssignmentInterface.TopicInfo> changelogTopics = mkMap(
            mkEntry("changelogTopic1", new StreamsAssignmentInterface.TopicInfo(Optional.empty(), Optional.of((short) 1), Collections.emptyMap())),
            mkEntry("changelogTopic2", new StreamsAssignmentInterface.TopicInfo(Optional.empty(), Optional.of((short) 2), Collections.emptyMap())),
            mkEntry("changelogTopic3", new StreamsAssignmentInterface.TopicInfo(Optional.empty(), Optional.of((short) 3), Collections.emptyMap()))
        );
        final Collection<Set<String>> copartitionGroup = mkSet(
            mkSet("sourceTopic1", "repartitionTopic2"),
            mkSet("sourceTopic2", "repartitionTopic1")
        );
        final StreamsAssignmentInterface.Subtopology subtopology1 = new StreamsAssignmentInterface.Subtopology(
            sourceTopics,
            sinkTopics,
            repartitionTopics,
            changelogTopics,
            copartitionGroup
        );
        final String subtopologyName1 = "subtopology1";
        when(streamsAssignmentInterface.subtopologyMap()).thenReturn(
            mkMap(mkEntry(subtopologyName1, subtopology1))
        );
        final StreamsGroupInitializeRequestManager streamsGroupInitializeRequestManager = new StreamsGroupInitializeRequestManager(
            logContext,
            groupId,
            streamsAssignmentInterface,
            coordinatorRequestManager
        );

        streamsGroupInitializeRequestManager.initialize();
        final NetworkClientDelegate.PollResult pollResult = streamsGroupInitializeRequestManager.poll(0);

        assertEquals(1, pollResult.unsentRequests.size());
        final NetworkClientDelegate.UnsentRequest unsentRequest = pollResult.unsentRequests.get(0);
        assertTrue(unsentRequest.node().isPresent());
        assertEquals(node, unsentRequest.node().get());
        assertEquals(ApiKeys.STREAMS_GROUP_INITIALIZE, unsentRequest.requestBuilder().apiKey());
        final StreamsGroupInitializeRequest.Builder streamsGroupInitializeRequestBuilder = (StreamsGroupInitializeRequest.Builder) unsentRequest.requestBuilder();
        final StreamsGroupInitializeRequest streamsGroupInitializeRequest = streamsGroupInitializeRequestBuilder.build();
        final StreamsGroupInitializeRequestData streamsGroupInitializeRequestData = streamsGroupInitializeRequest.data();
        assertEquals(ApiKeys.STREAMS_GROUP_INITIALIZE.id, streamsGroupInitializeRequestData.apiKey());
        assertEquals(groupId, streamsGroupInitializeRequestData.groupId());
        assertNotNull(streamsGroupInitializeRequestData.topology());
        final List<StreamsGroupInitializeRequestData.Subtopology> subtopologies = streamsGroupInitializeRequestData.topology();
        assertEquals(1, subtopologies.size());
        final StreamsGroupInitializeRequestData.Subtopology subtopology = subtopologies.get(0);
        assertEquals(subtopologyName1, subtopology.subtopologyId());
        assertEquals(Arrays.asList("sourceTopic1", "sourceTopic2"), subtopology.sourceTopics());
        assertEquals(Arrays.asList("sinkTopic1", "sinkTopic2", "sinkTopic3"), subtopology.repartitionSinkTopics());
        assertEquals(repartitionTopics.size(), subtopology.repartitionSourceTopics().size());
        subtopology.repartitionSourceTopics().forEach(topicInfo -> {
            final StreamsAssignmentInterface.TopicInfo repartitionTopic = repartitionTopics.get(topicInfo.name());
            assertEquals(repartitionTopic.numPartitions.get(), topicInfo.partitions());
            assertEquals(repartitionTopic.replicationFactor.get(), topicInfo.replicationFactor());
        });
        assertEquals(changelogTopics.size(), subtopology.stateChangelogTopics().size());
        subtopology.stateChangelogTopics().forEach(topicInfo -> {
            assertTrue(changelogTopics.containsKey(topicInfo.name()));
            assertEquals(0, topicInfo.partitions());
            final StreamsAssignmentInterface.TopicInfo changelogTopic = changelogTopics.get(topicInfo.name());
            assertEquals(changelogTopic.replicationFactor.get(), topicInfo.replicationFactor());
        });

        assertEquals(2, subtopology.copartitionGroups().size());
        final StreamsGroupInitializeRequestData.CopartitionGroup copartitionGroupData1 = subtopology.copartitionGroups().get(0);
        assertEquals(Collections.singletonList((short) 0), copartitionGroupData1.sourceTopics());
        assertEquals(Collections.singletonList((short) 1), copartitionGroupData1.repartitionSourceTopics());
        final StreamsGroupInitializeRequestData.CopartitionGroup copartitionGroupData2 = subtopology.copartitionGroups().get(1);
        assertEquals(Collections.singletonList((short) 1), copartitionGroupData2.sourceTopics());
        assertEquals(Collections.singletonList((short) 0), copartitionGroupData2.repartitionSourceTopics());
    }
}